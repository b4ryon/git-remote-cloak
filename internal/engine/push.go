// The push half of the engine: per-ref fast-forward decisions against the
// remote manifest, pack creation (only objects the remote lacks, encrypted
// while streaming out of git pack-objects), chained-CAS commit construction,
// and the retry loop that re-fetches, merges manifests, and re-plans when a
// concurrent push wins the compare-and-swap.
package engine

import (
	"bytes"
	"encoding/binary"
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

// pushAttempt is the outcome of one Push iteration. When done is true the push
// resolved and Push returns (results, state, nil); when done is false a
// compare-and-swap was lost and state is the re-fetched remote the next attempt
// retries against. state is read only on those success paths: the sole caller
// ignores Push's RemoteState whenever err != nil, so the error paths leave it
// nil (the existing "newer than rs even on failure" guarantee is carried by the
// loop's own cur, returned by Push directly).
type pushAttempt struct {
	results []RefResult
	state   *RemoteState
	done    bool
}

// Push executes the full push algorithm against the validated remote state
// and returns per-ref results plus the post-push remote state (which may be
// newer than rs even on failure, after CAS retries re-fetched). It owns only
// the retry loop: each iteration delegates one attempt to pushOnce and, on a
// lost compare-and-swap, retries against the re-fetched state until PushRetries
// is exhausted.
func (e *Engine) Push(rs *RemoteState, updates []RefUpdate, dryRun bool) ([]RefResult, *RemoteState, error) {
	cur := rs
	for attempt := 0; attempt <= e.Cfg.PushRetries; attempt++ {
		a, err := e.pushOnce(cur, updates, dryRun, attempt)
		if err != nil {
			return nil, cur, err
		}
		if a.done {
			return a.results, a.state, nil
		}
		cur = a.state
	}
	return nil, cur, cloakerr.Newfh(cloakerr.CASExhausted, "push",
		"another client keeps winning the race; wait for the other machine's sync to finish and re-run `git push`, or raise `git config cloak.pushRetries`",
		"lost the compare-and-swap race %d times in a row; remote is under heavy concurrent pushing", e.Cfg.PushRetries+1)
}

// pushOnce runs a single push attempt against cur: plan the refs, optionally
// consolidate, build and execute the backend commit, then resolve the result.
// It reports done=true with the final results/state when the push resolves
// (accepted, no-op, or dry-run), or done=false with the re-fetched state when
// the compare-and-swap is lost so the caller can retry.
func (e *Engine) pushOnce(cur *RemoteState, updates []RefUpdate, dryRun bool, attempt int) (pushAttempt, error) {
	results, plan, err := e.preparePush(cur, updates)
	if err != nil {
		return pushAttempt{}, err
	}
	if plan == nil {
		// Nothing was accepted (every ref rejected or a pure no-op).
		return pushAttempt{results: results, state: cur, done: true}, nil
	}
	if dryRun {
		e.Log.Info("dry-run: skipping backend push", "generation", plan.man.Generation)
		plan.abort()
		return pushAttempt{results: results, state: cur, done: true}, nil
	}

	squash, err := e.maybeConsolidate(cur, plan)
	if err != nil {
		plan.abort()
		return pushAttempt{}, err
	}

	res, bc, err := e.commitAndExecute(cur, plan, squash, attempt)
	plan.abort()
	if err != nil {
		return pushAttempt{}, err
	}
	switch res {
	case backend.PushOK:
		return e.acceptPush(results, plan, bc, updates, attempt)
	case backend.PushCASLost:
		return e.retryAfterCASLost(attempt)
	}
	return pushAttempt{state: cur, done: false}, nil
}

// acceptPush records a backend-accepted push (the PushOK arm of pushOnce):
// it persists the pin/repo-id/applied state, logs acceptance, and returns the
// resolved attempt carrying the new remote state.
func (e *Engine) acceptPush(results []RefResult, plan *pushPlan, bc builtCommit, updates []RefUpdate, attempt int) (pushAttempt, error) {
	if err := e.persistPushed(plan.man.Generation, bc.manifestHash, plan.man.RepoID, plan.packID, plan.markApplied); err != nil {
		return pushAttempt{}, err
	}
	e.Log.Info("push accepted", "generation", plan.man.Generation,
		"attempt", attempt, "new_pack", plan.packID != "", "refs", len(updates))
	return pushAttempt{results: results, state: &RemoteState{Head: bc.commit, Manifest: plan.man, ManifestHash: bc.manifestHash}, done: true}, nil
}

// retryAfterCASLost handles the PushCASLost arm of pushOnce: it re-fetches the
// remote state and returns a not-done attempt so the Push loop retries the next
// attempt against it. The per-attempt results are recomputed on the next
// iteration, so they are not carried forward here.
func (e *Engine) retryAfterCASLost(attempt int) (pushAttempt, error) {
	// Warn (not Info) so the user sees progress on stderr: a contended push
	// otherwise looks like a silent hang while it retries.
	e.Log.Warn("compare-and-swap lost; re-fetching and retrying", "attempt", attempt)
	next, err := e.LoadRemoteState()
	if err != nil {
		return pushAttempt{}, err
	}
	return pushAttempt{state: next, done: false}, nil
}

// maybeConsolidate runs the geometric check (DESIGN.md push step 4): when the
// remote has a head and enough packs accumulate (GeometricFactor>0 and at least
// two victims), it rewrites plan's pack set into a single squashing pack and
// reports squash=true, turning the upcoming backend push into a lease-guarded
// force-push. Otherwise plan is left untouched and squash is false.
func (e *Engine) maybeConsolidate(cur *RemoteState, plan *pushPlan) (squash bool, err error) {
	if cur == nil || cur.Head == "" || e.Cfg.GeometricFactor <= 0 {
		return false, nil
	}
	victims := geometry.Victims(plan.man.Packs, e.Cfg.GeometricFactor)
	if len(victims) < 2 {
		return false, nil
	}
	if err := e.consolidate(cur, plan, victims); err != nil {
		return false, err
	}
	return true, nil
}

// commitAndExecute assembles the backend commit for plan and pushes it. A
// non-squash push chains onto cur (parent=cur.Head) and reuses its pack blobs;
// a squash re-roots the chain (no parent) but still reuses surviving blobs and
// pushes under a lease against cur.Head. The returned PushResult is meaningful
// only when err is nil. plan is NOT aborted here; the caller owns its cleanup.
func (e *Engine) commitAndExecute(cur *RemoteState, plan *pushPlan, squash bool, attempt int) (backend.PushResult, builtCommit, error) {
	parent, blobSource := "", ""
	if cur != nil {
		blobSource = cur.Head
		if !squash {
			parent = cur.Head
		}
	}
	bc, err := e.buildBackendCommit(commitInput{
		man: plan.man, packID: plan.packID, packPath: plan.packPath,
		blobSource: blobSource, parent: parent, key: e.Key,
	})
	if err != nil {
		return 0, builtCommit{}, err
	}
	holdHook(attempt)
	if squash {
		e.Log.Info("geometric consolidation triggered; squashing backend chain",
			"generation", plan.man.Generation, "live_packs", len(plan.man.Packs))
		res, err := e.Be.PushLease(bc.commit, cur.Head)
		return res, bc, err
	}
	res, err := e.Be.PushFF(bc.commit)
	return res, bc, err
}

// persistPushed records a freshly accepted push locally: the manifest pin, the
// repo id, and (when markApplied and a pack was added) the new pack as already
// applied. Called only after the backend reports backend.PushOK.
func (e *Engine) persistPushed(gen uint64, hash, repoID, packID string, markApplied bool) error {
	if err := e.St.SavePin(state.Pin{Generation: gen, ManifestHash: hash}); err != nil {
		return err
	}
	if err := e.St.SaveRepoID(repoID); err != nil {
		return err
	}
	if markApplied && packID != "" {
		if err := e.St.MarkApplied(packID); err != nil {
			return err
		}
	}
	return nil
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

	results, newRefs, wants, accepted := e.planRefUpdates(remoteRefs, updates)
	if accepted == 0 {
		return results, nil, nil
	}

	plan, err := e.buildPlanPack(wants, remoteRefs)
	if err != nil {
		return nil, nil, err
	}
	if err := e.assembleManifest(curMan, newRefs, plan); err != nil {
		return nil, nil, err
	}
	return results, plan, nil
}

// planRefUpdates applies each ref update against remoteRefs without touching
// any backend state, returning the per-ref results, the projected ref set
// (remoteRefs plus accepted creates/updates minus accepted deletes), the oids
// to pack as wants, and the count of accepted updates.
func (e *Engine) planRefUpdates(remoteRefs map[string]string, updates []RefUpdate) (results []RefResult, newRefs map[string]string, wants []string, accepted int) {
	results = make([]RefResult, 0, len(updates))
	newRefs = map[string]string{}
	for k, v := range remoteRefs {
		newRefs[k] = v
	}
	for _, u := range updates {
		res, ok, del, setOID := e.decideRef(u, remoteRefs)
		results = append(results, res)
		if !ok {
			continue
		}
		accepted++
		if del {
			delete(newRefs, u.Dst)
		} else {
			newRefs[u.Dst] = setOID
			wants = append(wants, setOID)
		}
	}
	return results, newRefs, wants, accepted
}

// buildPlanPack creates a fresh pushPlan and, when there are wants, encrypts a
// pack of the missing objects into it. An empty pack (count==0) is discarded so
// the plan stays packless; only a non-empty pack sets markApplied.
func (e *Engine) buildPlanPack(wants []string, remoteRefs map[string]string) (*pushPlan, error) {
	plan := &pushPlan{}
	if len(wants) > 0 {
		bp, err := e.buildPack(wants, remoteRefs)
		if err != nil {
			return nil, err
		}
		if bp.count > 0 {
			plan.packID, plan.packPath, plan.packSize = bp.id, bp.path, bp.size
			plan.markApplied = true
		} else if bp.path != "" {
			_ = os.Remove(bp.path)
		}
	}
	return plan, nil
}

// assembleManifest builds the new manifest from curMan (or mints a fresh repo
// identity on first push), wires in newRefs and any pack from plan, validates
// it, and stores it on plan. A validation failure aborts the plan's pack.
func (e *Engine) assembleManifest(curMan *manifest.Manifest, newRefs map[string]string, plan *pushPlan) error {
	man := manifest.New()
	if curMan != nil {
		man = curMan.Clone()
	} else {
		// First push to an empty remote: mint this repository's identity,
		// bound inside the AEAD manifest and pinned locally on success.
		id, err := manifest.NewRepoID()
		if err != nil {
			return cloakerr.New(cloakerr.Crypto, "mint repo id", err)
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
		return fmt.Errorf("constructed manifest invalid (bug): %w", err)
	}
	plan.man = man
	return nil
}

// decideRef evaluates one push refspec against the current remote refs without
// mutating any state. res is what gets reported for u.Dst. When accepted is
// false the ref was rejected (res.Err explains why). When accepted is true
// exactly one outcome applies: del means delete u.Dst from the manifest;
// otherwise setOID is the oid to publish for u.Dst and to add to the pack
// wants. A rejection never touches the manifest, so the caller can append res
// and continue.
func (e *Engine) decideRef(u RefUpdate, remoteRefs map[string]string) (res RefResult, accepted, del bool, setOID string) {
	if u.Src == "" {
		if _, ok := remoteRefs[u.Dst]; !ok {
			return RefResult{u.Dst, "remote ref does not exist"}, false, false, ""
		}
		return RefResult{u.Dst, ""}, true, true, ""
	}
	oid, err := e.G.Out(gitx.Opts{GitDir: e.LocalGitDir}, "rev-parse", "--verify", u.Src+"^{}")
	if err != nil {
		return RefResult{u.Dst, "cannot resolve " + u.Src + " to a commit"}, false, false, ""
	}
	// For annotated tags push the tag object itself, not the peel.
	refOID, err := e.G.Out(gitx.Opts{GitDir: e.LocalGitDir}, "rev-parse", "--verify", u.Src)
	if err != nil {
		return RefResult{u.Dst, "cannot resolve ref " + u.Src}, false, false, ""
	}
	if reason := e.nonFastForwardReason(u, remoteRefs, oid, refOID); reason != "" {
		return RefResult{u.Dst, reason}, false, false, ""
	}
	return RefResult{u.Dst, ""}, true, false, refOID
}

// nonFastForwardReason reports why publishing refOID over the remote's current
// u.Dst would not be a fast-forward, or "" when the update is allowed (the ref
// is new, the push is forced, the tip is unchanged, or it is a true
// fast-forward). oid is the peeled commit used for the ancestry test.
func (e *Engine) nonFastForwardReason(u RefUpdate, remoteRefs map[string]string, oid, refOID string) string {
	old, exists := remoteRefs[u.Dst]
	if !exists || u.Force || old == refOID {
		return ""
	}
	if !e.HaveObject(old) {
		return "fetch first"
	}
	if _, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir},
		"merge-base", "--is-ancestor", old, oid); err != nil {
		return "non-fast-forward"
	}
	return ""
}

// streamPack runs `git pack-objects` (with the given opts and extra args),
// streaming the encrypted result into pw, then finalizes pw. The caller
// creates pw (so it controls the master key) and sets opts.Stdout to pw, or
// to a wrapper over it such as a header sniffer. packCtx and finalizeCtx name
// the two failure points for error messages; pw is aborted on any failure.
func (e *Engine) streamPack(pw *agecrypt.PackWriter, opts gitx.Opts, packCtx, finalizeCtx string, args ...string) error {
	if _, _, err := e.G.Run(opts, append([]string{"pack-objects"}, args...)...); err != nil {
		pw.Abort()
		return cloakerr.New(cloakerr.LocalGit, packCtx, err)
	}
	if err := pw.Close(); err != nil {
		pw.Abort()
		return cloakerr.New(cloakerr.Crypto, finalizeCtx, err)
	}
	return nil
}

// builtPack is the result of buildPack: a freshly encrypted pack's identity
// (id), its temp ciphertext file (path) and ciphertext size, and the object
// count sniffed from the pack header. count==0 means an empty pack the caller
// discards.
type builtPack struct {
	id    string
	path  string
	size  int64
	count uint32
}

// buildPack streams `git pack-objects` (wants minus the remote's haves)
// through the encryptor into a temp file, sniffing the pack header for the
// object count so empty packs are dropped.
func (e *Engine) buildPack(wants []string, remoteRefs map[string]string) (builtPack, error) {
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
		return builtPack{}, err
	}
	sniff := &packHeadSniffer{dst: pw}
	if err := e.streamPack(pw, gitx.Opts{GitDir: e.LocalGitDir,
		Stdin:  strings.NewReader(stdin.String()),
		Stdout: sniff},
		"pack objects", "finalize pack",
		"--revs", "--stdout", "--delta-base-offset"); err != nil {
		return builtPack{}, err
	}
	e.Log.Info("built pack", "objects", sniff.count(), "ciphertext_bytes", pw.Size())
	return builtPack{id: pw.ID(), path: pw.Path(), size: pw.Size(), count: sniff.count()}, nil
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

// builtCommit is the result of buildBackendCommit: the new backend commit oid
// (which becomes RemoteState.Head) and the manifest ciphertext hash (the
// rollback pin, RemoteState.ManifestHash). Bundling the two same-typed strings
// keeps callers from threading a positionally-ambiguous (commit, hash) pair.
type builtCommit struct {
	commit       string
	manifestHash string
}

// buildBackendCommit encrypts and hashes the manifest, hashes the new pack
// blob, assembles the tree (reusing surviving pack blobs from blobSource),
// and creates the chained or squash commit. Returns the commit oid and the
// manifest ciphertext hash.
func (e *Engine) buildBackendCommit(in commitInput) (builtCommit, error) {
	manifestOID, manifestHash, err := e.encryptManifestBlob(in.man, in.key)
	if err != nil {
		return builtCommit{}, err
	}
	packOIDs, err := e.treePackBlobs(in)
	if err != nil {
		return builtCommit{}, err
	}
	commit, err := e.Be.BuildCommit(in.parent, manifestOID, packOIDs, in.man.Generation)
	if err != nil {
		return builtCommit{}, err
	}
	return builtCommit{commit: commit, manifestHash: manifestHash}, nil
}

// encryptManifestBlob encodes and encrypts the manifest, then hashes the
// ciphertext into a backend blob. Returns the manifest blob oid and the
// ciphertext hash (the rollback pin value).
func (e *Engine) encryptManifestBlob(man *manifest.Manifest, key keystore.Key) (manifestOID, manifestHash string, err error) {
	plain, err := manifest.Encode(man)
	if err != nil {
		return "", "", err
	}
	ct, err := agecrypt.EncryptBytes(key, plain)
	if err != nil {
		return "", "", err
	}
	manifestHash = ciphertextHash(ct)
	manifestOID, err = e.Be.HashObject(bytes.NewReader(ct))
	if err != nil {
		return "", "", err
	}
	return manifestOID, manifestHash, nil
}

// treePackBlobs assembles the pack id -> blob oid map for the new commit's
// tree: it reuses surviving pack blobs from blobSource (dropping any no longer
// live in the manifest) and hashes the new pack ciphertext when present.
func (e *Engine) treePackBlobs(in commitInput) (map[string]string, error) {
	packOIDs, err := e.Be.PackBlobOIDs(in.blobSource)
	if err != nil {
		return nil, err
	}
	// Keep only blobs for packs still live in the manifest.
	live := in.man.PackIDs()
	for id := range packOIDs {
		if !live[id] {
			delete(packOIDs, id)
		}
	}
	if in.packID != "" {
		oid, err := e.hashPackBlob(in.packPath)
		if err != nil {
			return nil, err
		}
		packOIDs[in.packID] = oid
	}
	return packOIDs, nil
}

// hashPackBlob opens the new pack ciphertext at path and returns the blob oid
// the backend would store it under, so treePackBlobs can add it to the tree map.
func (e *Engine) hashPackBlob(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return e.Be.HashObject(f)
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
