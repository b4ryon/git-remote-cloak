// Consolidation and full repack: merging victim packs into one (sourcing
// objects from the packs themselves via a scratch repository, NOT from the
// local repo, which may have pruned remote-live objects), and the explicit
// full repack / rekey operation that packs only reachable objects from the
// local repository and squashes the backend chain under a lease push.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
	"github.com/b4ryon/git-remote-cloak/internal/state"
)

// consolidate merges the victim packs into one and rewrites plan in place:
// the new pack carries Replaces so up-to-date clients skip the download,
// and the resulting push becomes a squash.
func (e *Engine) consolidate(cur *RemoteState, plan *pushPlan, victims []manifest.Pack) error {
	scratch, err := os.MkdirTemp(e.St.TmpDir(), "scratch-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	scratchGit := filepath.Join(scratch, "odb.git")
	if _, _, err := e.G.Run(gitx.Opts{Scrub: true}, "init", "--bare", "--quiet", scratchGit); err != nil {
		return cloakerr.New(cloakerr.LocalGit, "init scratch repo", err)
	}

	applied, err := e.St.AppliedSet()
	if err != nil {
		return err
	}
	canMark := true
	victimIDs := make([]string, 0, len(victims))
	for _, v := range victims {
		victimIDs = append(victimIDs, v.ID)
		localPath := ""
		if v.ID == plan.packID {
			localPath = plan.packPath
		} else if !applied[v.ID] {
			canMark = false
		}
		if err := e.indexPackInto(scratchGit, cur.Head, v, localPath); err != nil {
			return err
		}
	}

	objects, _, err := e.G.Run(gitx.Opts{GitDir: scratchGit},
		"cat-file", "--batch-all-objects", "--batch-check=%(objectname)")
	if err != nil {
		return cloakerr.New(cloakerr.LocalGit, "enumerate scratch objects", err)
	}
	pw, err := agecrypt.NewPackWriter(e.St.TmpDir(), e.Key)
	if err != nil {
		return err
	}
	if _, _, err := e.G.Run(gitx.Opts{GitDir: scratchGit,
		Stdin: strings.NewReader(objects), Stdout: pw},
		"pack-objects", "--stdout", "--delta-base-offset"); err != nil {
		pw.Abort()
		return cloakerr.New(cloakerr.LocalGit, "pack consolidated objects", err)
	}
	if err := pw.Close(); err != nil {
		pw.Abort()
		return cloakerr.New(cloakerr.Crypto, "finalize consolidated pack", err)
	}

	inVictims := map[string]bool{}
	for _, id := range victimIDs {
		inVictims[id] = true
	}
	var liveSurvivors []manifest.Pack
	for _, p := range plan.man.Packs {
		if !inVictims[p.ID] {
			liveSurvivors = append(liveSurvivors, p)
		}
	}
	if plan.packPath != "" {
		_ = os.Remove(plan.packPath)
	}
	plan.man.Packs = append(liveSurvivors,
		manifest.Pack{ID: pw.ID(), Size: pw.Size(), Replaces: victimIDs})
	plan.packID, plan.packPath, plan.packSize = pw.ID(), pw.Path(), pw.Size()
	plan.markApplied = canMark
	if err := plan.man.Validate(); err != nil {
		return fmt.Errorf("consolidated manifest invalid (bug): %w", err)
	}
	e.Log.Info("consolidated packs", "victims", len(victimIDs),
		"merged_bytes", pw.Size(), "live_packs", len(plan.man.Packs))
	return nil
}

// indexPackInto verifies, decrypts, and indexes one manifest pack into the
// given repository's object store. localPath supplies the ciphertext from
// disk (a not-yet-pushed pack); otherwise it is downloaded from the backend
// commit and hash-verified against its id.
func (e *Engine) indexPackInto(gitDir, head string, p manifest.Pack, localPath string) error {
	short := p.ID[:12]
	ctPath := localPath
	if ctPath == "" {
		ctPath = filepath.Join(e.St.TmpDir(), "cons-"+short+".age")
		defer os.Remove(ctPath)
		f, err := os.OpenFile(ctPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		hasher := sha256.New()
		if err := e.Be.ReadBlob(head, "packs/"+p.ID+".age", io.MultiWriter(f, hasher)); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if got := hex.EncodeToString(hasher.Sum(nil)); got != p.ID {
			return cloakerr.Newf(cloakerr.Tamper, "verify pack "+short,
				"ciphertext hash %s does not match manifest id %s", got, p.ID).WithHint(packTamperHint)
		}
	}
	ct, err := os.Open(ctPath)
	if err != nil {
		return err
	}
	defer ct.Close()
	plain, err := agecrypt.Decrypt(ct, e.Key)
	if err != nil {
		return cloakerr.WithHintOn(err, packTamperHint)
	}
	if _, _, err := e.G.Run(gitx.Opts{GitDir: gitDir, Stdin: plain},
		"index-pack", "--stdin"); err != nil {
		return cloakerr.New(cloakerr.LocalGit, "index pack "+short+" into scratch", err)
	}
	return nil
}

// FullRepack rebuilds the remote as a single pack of objects reachable from
// the manifest refs (sourced from the local repository), optionally under a
// new master key (rekey), and squashes the backend chain with a lease push.
func (e *Engine) FullRepack(rs *RemoteState, newKey *keystore.Key) (*RemoteState, error) {
	if rs == nil || rs.Manifest == nil {
		return nil, fmt.Errorf("cloak: remote is empty; nothing to repack")
	}
	key := e.Key
	if newKey != nil {
		key = *newKey
	}
	cur := rs
	for attempt := 0; attempt <= e.Cfg.PushRetries; attempt++ {
		// Apply inside the loop: after a lost compare-and-swap the reloaded
		// manifest may reference objects a concurrent push added, which the
		// local repository must hold before pack-objects can want them.
		if _, err := e.FetchApply(cur); err != nil {
			return nil, err
		}
		var wants strings.Builder
		for _, oid := range cur.Manifest.Refs {
			fmt.Fprintln(&wants, oid)
		}
		pw, err := agecrypt.NewPackWriter(e.St.TmpDir(), key)
		if err != nil {
			return nil, err
		}
		if _, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir,
			Stdin: strings.NewReader(wants.String()), Stdout: pw},
			"pack-objects", "--revs", "--stdout", "--delta-base-offset"); err != nil {
			pw.Abort()
			return nil, cloakerr.New(cloakerr.LocalGit, "pack reachable objects", err)
		}
		if err := pw.Close(); err != nil {
			pw.Abort()
			return nil, cloakerr.New(cloakerr.Crypto, "finalize repack pack", err)
		}

		oldIDs := make([]string, 0, len(cur.Manifest.Packs))
		for _, p := range cur.Manifest.Packs {
			oldIDs = append(oldIDs, p.ID)
		}
		man := cur.Manifest.Clone()
		man.Generation++
		man.Packs = []manifest.Pack{{ID: pw.ID(), Size: pw.Size(), Replaces: oldIDs}}

		commit, hash, err := e.buildBackendCommit(commitInput{
			man: man, packID: pw.ID(), packPath: pw.Path(),
			blobSource: "", parent: "", key: key,
		})
		_ = os.Remove(pw.Path())
		if err != nil {
			return nil, err
		}
		res, err := e.Be.PushLease(commit, cur.Head)
		switch {
		case err != nil:
			return nil, err
		case res == backend.PushOK:
			if err := e.St.SavePin(state.Pin{Generation: man.Generation, ManifestHash: hash}); err != nil {
				return nil, err
			}
			if err := e.St.SaveRepoID(man.RepoID); err != nil {
				return nil, err
			}
			if err := e.St.MarkApplied(man.Packs[0].ID); err != nil {
				return nil, err
			}
			e.Log.Info("full repack pushed", "generation", man.Generation,
				"pack_bytes", man.Packs[0].Size, "rekeyed", newKey != nil)
			return &RemoteState{Head: commit, Manifest: man, ManifestHash: hash}, nil
		case res == backend.PushCASLost:
			e.Log.Info("repack lost compare-and-swap; re-fetching and retrying", "attempt", attempt)
			cur, err = e.LoadRemoteState()
			if err != nil {
				return nil, err
			}
		}
	}
	return nil, cloakerr.Newfh(cloakerr.CASExhausted, "repack",
		"another client keeps winning the push race; wait for other syncs to settle and re-run `git cloak repack`/`rekey`, or raise `git config cloak.pushRetries`",
		"lost the compare-and-swap race %d times in a row", e.Cfg.PushRetries+1)
}
