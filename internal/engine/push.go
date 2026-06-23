// The push half of the engine: per-ref fast-forward decisions against the
// remote manifest, pack creation (only objects the remote lacks, encrypted
// while streaming out of git pack-objects), chained-CAS commit construction,
// and the retry loop that re-fetches, merges manifests, and re-plans when a
// concurrent push wins the compare-and-swap.
package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/geometry"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
	"github.com/b4ryon/git-remote-cloak/internal/state"
)

// holdHookEnv names the test-only synchronization hook: when set to a
// directory, the FIRST push attempt touches <dir>/waiting and blocks until
// <dir>/release exists. Inert when unset (asserted by the security suite).
const holdHookEnv = "CLOAK_TEST_HOLD_BEFORE_PUSH"

// RefUpdate is one "push [+]src:dst" refspec from git.
type RefUpdate struct {
	Src   string // local committish; "" means delete dst
	Dst   string // remote ref name
	Force bool
}

// RefResult is the per-ref outcome reported back over the protocol.
type RefResult struct {
	Dst string
	Err string // "" = ok
}

// Push executes the full push algorithm against the validated remote state
// and returns per-ref results plus the post-push remote state (which may be
// newer than rs even on failure, after CAS retries re-fetched).
func (e *Engine) Push(rs *RemoteState, updates []RefUpdate, dryRun bool) ([]RefResult, *RemoteState, error) {
	cur := rs
	for attempt := 0; attempt <= e.Cfg.PushRetries; attempt++ {
		results, plan, err := e.preparePush(cur, updates)
		if err != nil {
			return nil, cur, err
		}
		if plan == nil {
			// Nothing was accepted (every ref rejected or a pure no-op).
			return results, cur, nil
		}
		if dryRun {
			e.Log.Info("dry-run: skipping backend push", "generation", plan.man.Generation)
			plan.abort()
			return results, cur, nil
		}

		// Geometric check (DESIGN.md push step 4): consolidation rewrites
		// the pack set and turns this push into a squash.
		squash := false
		if cur != nil && cur.Head != "" && e.Cfg.GeometricFactor > 0 {
			if victims := geometry.Victims(plan.man.Packs, e.Cfg.GeometricFactor); len(victims) >= 2 {
				if err := e.consolidate(cur, plan, victims); err != nil {
					plan.abort()
					return nil, cur, err
				}
				squash = true
			}
		}
		parent, blobSource := "", ""
		if cur != nil {
			blobSource = cur.Head
			if !squash {
				parent = cur.Head
			}
		}
		commit, hash, err := e.buildBackendCommit(commitInput{
			man: plan.man, packID: plan.packID, packPath: plan.packPath,
			blobSource: blobSource, parent: parent, key: e.Key,
		})
		if err != nil {
			plan.abort()
			return nil, cur, err
		}
		holdHook(attempt)
		var res backend.PushResult
		if squash {
			e.Log.Info("geometric consolidation triggered; squashing backend chain",
				"generation", plan.man.Generation, "live_packs", len(plan.man.Packs))
			res, err = e.Be.PushLease(commit, cur.Head)
		} else {
			res, err = e.Be.PushFF(commit)
		}
		plan.abort()
		switch {
		case err != nil:
			return nil, cur, err
		case res == backend.PushOK:
			if err := e.St.SavePin(state.Pin{Generation: plan.man.Generation, ManifestHash: hash}); err != nil {
				return nil, cur, err
			}
			if err := e.St.SaveRepoID(plan.man.RepoID); err != nil {
				return nil, cur, err
			}
			if plan.packID != "" && plan.markApplied {
				if err := e.St.MarkApplied(plan.packID); err != nil {
					return nil, cur, err
				}
			}
			e.Log.Info("push accepted", "generation", plan.man.Generation,
				"attempt", attempt, "new_pack", plan.packID != "", "refs", len(updates))
			return results, &RemoteState{Head: commit, Manifest: plan.man, ManifestHash: hash}, nil
		case res == backend.PushCASLost:
			// Warn (not Info) so the user sees progress on stderr: a contended
			// push otherwise looks like a silent hang while it retries.
			e.Log.Warn("compare-and-swap lost; re-fetching and retrying", "attempt", attempt)
			cur, err = e.LoadRemoteState()
			if err != nil {
				return nil, cur, err
			}
			continue
		}
	}
	return nil, cur, cloakerr.Newfh(cloakerr.CASExhausted, "push",
		"another client keeps winning the race; wait for the other machine's sync to finish and re-run `git push`, or raise `git config cloak.pushRetries`",
		"lost the compare-and-swap race %d times in a row; remote is under heavy concurrent pushing", e.Cfg.PushRetries+1)
}

// pushPlan carries one prepared attempt: the new manifest, the encrypted
// pack temp file (if any), and cleanup. markApplied records whether the
// pack's objects are known to exist locally (own pushes yes; a
// consolidation that merged never-applied packs no).
type pushPlan struct {
	man         *manifest.Manifest
	packID      string
	packPath    string
	packSize    int64
	markApplied bool
}

func (p *pushPlan) abort() {
	if p != nil && p.packPath != "" {
		_ = os.Remove(p.packPath)
	}
}

// preparePush makes the per-ref decisions against cur and assembles the new
// manifest plus the encrypted pack of missing objects. plan==nil means no
// ref update was accepted.
func (e *Engine) preparePush(cur *RemoteState, updates []RefUpdate) ([]RefResult, *pushPlan, error) {
	var curMan *manifest.Manifest
	if cur != nil {
		curMan = cur.Manifest
	}
	remoteRefs := map[string]string{}
	if curMan != nil {
		remoteRefs = curMan.Refs
	}

	results := make([]RefResult, 0, len(updates))
	newRefs := map[string]string{}
	for k, v := range remoteRefs {
		newRefs[k] = v
	}
	var wants []string
	accepted := 0
	for _, u := range updates {
		switch {
		case u.Src == "":
			if _, ok := remoteRefs[u.Dst]; !ok {
				results = append(results, RefResult{u.Dst, "remote ref does not exist"})
				continue
			}
			delete(newRefs, u.Dst)
			results = append(results, RefResult{u.Dst, ""})
			accepted++
		default:
			oid, err := e.G.Out(gitx.Opts{GitDir: e.LocalGitDir}, "rev-parse", "--verify", u.Src+"^{}")
			if err != nil {
				results = append(results, RefResult{u.Dst, "cannot resolve " + u.Src + " to a commit"})
				continue
			}
			// For annotated tags push the tag object itself, not the peel.
			refOID, err := e.G.Out(gitx.Opts{GitDir: e.LocalGitDir}, "rev-parse", "--verify", u.Src)
			if err != nil {
				results = append(results, RefResult{u.Dst, "cannot resolve ref " + u.Src})
				continue
			}
			if old, exists := remoteRefs[u.Dst]; exists && !u.Force && old != refOID {
				if !e.HaveObject(old) {
					results = append(results, RefResult{u.Dst, "fetch first"})
					continue
				}
				if _, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir},
					"merge-base", "--is-ancestor", old, oid); err != nil {
					results = append(results, RefResult{u.Dst, "non-fast-forward"})
					continue
				}
			}
			newRefs[u.Dst] = refOID
			wants = append(wants, refOID)
			results = append(results, RefResult{u.Dst, ""})
			accepted++
		}
	}
	if accepted == 0 {
		return results, nil, nil
	}

	plan := &pushPlan{}
	if len(wants) > 0 {
		id, path, size, count, err := e.buildPack(wants, remoteRefs)
		if err != nil {
			return nil, nil, err
		}
		if count > 0 {
			plan.packID, plan.packPath, plan.packSize = id, path, size
			plan.markApplied = true
		} else if path != "" {
			_ = os.Remove(path)
		}
	}

	man := manifest.New()
	if curMan != nil {
		man = curMan.Clone()
	} else {
		// First push to an empty remote: mint this repository's identity,
		// bound inside the AEAD manifest and pinned locally on success.
		id, err := manifest.NewRepoID()
		if err != nil {
			return nil, nil, cloakerr.New(cloakerr.Crypto, "mint repo id", err)
		}
		man.RepoID = id
		// cloak hides contents but not the repo's existence, name, owner, or
		// push metadata; the helper cannot verify host privacy over plain git.
		e.Log.Warn("creating a new cloak backend on this remote; ensure the host repository is PRIVATE (cloak hides contents, not the repo's existence/name/owner or push timing and sizes)")
	}
	man.Generation++
	man.Refs = newRefs
	man.Head = e.headForManifest(curMan, newRefs)
	if plan.packID != "" {
		man.Packs = append(man.Packs, manifest.Pack{ID: plan.packID, Size: plan.packSize})
	}
	if err := man.Validate(); err != nil {
		plan.abort()
		return nil, nil, fmt.Errorf("constructed manifest invalid (bug): %w", err)
	}
	plan.man = man
	return results, plan, nil
}

// buildPack streams `git pack-objects` (wants minus the remote's haves)
// through the encryptor into a temp file, sniffing the pack header for the
// object count so empty packs are dropped.
func (e *Engine) buildPack(wants []string, remoteRefs map[string]string) (id, path string, size int64, count uint32, err error) {
	var stdin strings.Builder
	for _, w := range wants {
		fmt.Fprintln(&stdin, w)
	}
	stdin.WriteString("--not\n")
	for _, oid := range remoteRefs {
		if e.HaveObject(oid) {
			fmt.Fprintln(&stdin, oid)
		}
	}

	pw, err := agecrypt.NewPackWriter(e.St.TmpDir(), e.Key)
	if err != nil {
		return "", "", 0, 0, err
	}
	sniff := &packHeadSniffer{dst: pw}
	_, _, err = e.G.Run(gitx.Opts{GitDir: e.LocalGitDir,
		Stdin:  strings.NewReader(stdin.String()),
		Stdout: sniff},
		"pack-objects", "--revs", "--stdout", "--delta-base-offset")
	if err != nil {
		pw.Abort()
		return "", "", 0, 0, cloakerr.New(cloakerr.LocalGit, "pack objects", err)
	}
	if err := pw.Close(); err != nil {
		pw.Abort()
		return "", "", 0, 0, cloakerr.New(cloakerr.Crypto, "finalize pack", err)
	}
	e.Log.Info("built pack", "objects", sniff.count(), "ciphertext_bytes", pw.Size())
	return pw.ID(), pw.Path(), pw.Size(), sniff.count(), nil
}

// packHeadSniffer reads the object count from the 12-byte pack header
// ("PACK" + version + count, big-endian) while passing data through.
type packHeadSniffer struct {
	dst io.Writer
	hdr []byte
}

func (s *packHeadSniffer) Write(p []byte) (int, error) {
	if len(s.hdr) < 12 {
		take := 12 - len(s.hdr)
		if take > len(p) {
			take = len(p)
		}
		s.hdr = append(s.hdr, p[:take]...)
	}
	return s.dst.Write(p)
}

func (s *packHeadSniffer) count() uint32 {
	if len(s.hdr) < 12 {
		return 0
	}
	return binary.BigEndian.Uint32(s.hdr[8:12])
}

// headForManifest picks the manifest head: the local HEAD's branch when it
// is among the refs, else the previous head if still valid, else empty.
func (e *Engine) headForManifest(prev *manifest.Manifest, refs map[string]string) string {
	if local, err := e.G.Out(gitx.Opts{GitDir: e.LocalGitDir}, "symbolic-ref", "-q", "HEAD"); err == nil {
		if _, ok := refs[local]; ok {
			return local
		}
	}
	if prev != nil && prev.Head != "" {
		if _, ok := refs[prev.Head]; ok {
			return prev.Head
		}
	}
	return ""
}

// commitInput describes one backend commit to assemble.
type commitInput struct {
	man        *manifest.Manifest
	packID     string // new pack id ("" = manifest-only commit)
	packPath   string // ciphertext temp file holding the new pack
	blobSource string // commit whose packs/ blobs get reused ("" = none)
	parent     string // commit parent ("" = squash root commit)
	key        keystore.Key
}

// buildBackendCommit encrypts and hashes the manifest, hashes the new pack
// blob, assembles the tree (reusing surviving pack blobs from blobSource),
// and creates the chained or squash commit. Returns the commit oid and the
// manifest ciphertext hash.
func (e *Engine) buildBackendCommit(in commitInput) (commit, manifestHash string, err error) {
	plain, err := manifest.Encode(in.man)
	if err != nil {
		return "", "", err
	}
	ct, err := agecrypt.EncryptBytes(in.key, plain)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(ct)
	manifestHash = hex.EncodeToString(sum[:])

	manifestOID, err := e.Be.HashObject(bytes.NewReader(ct))
	if err != nil {
		return "", "", err
	}
	packOIDs, err := e.Be.PackBlobOIDs(in.blobSource)
	if err != nil {
		return "", "", err
	}
	// Keep only blobs for packs still live in the manifest.
	live := in.man.PackIDs()
	for id := range packOIDs {
		if !live[id] {
			delete(packOIDs, id)
		}
	}
	if in.packID != "" {
		f, err := os.Open(in.packPath)
		if err != nil {
			return "", "", err
		}
		oid, herr := e.Be.HashObject(f)
		f.Close()
		if herr != nil {
			return "", "", herr
		}
		packOIDs[in.packID] = oid
	}
	commit, err = e.Be.BuildCommit(in.parent, manifestOID, packOIDs, in.man.Generation)
	if err != nil {
		return "", "", err
	}
	return commit, manifestHash, nil
}

// holdHook implements the test-only pre-push synchronization point.
func holdHook(attempt int) {
	dir := os.Getenv(holdHookEnv)
	if dir == "" || attempt != 0 {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "waiting"), []byte("1"), 0o600)
	for {
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
