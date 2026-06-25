// Consolidation and full repack: merging victim packs into one (sourcing
// objects from the packs themselves via a scratch repository, NOT from the
// local repo, which may have pruned remote-live objects), and the explicit
// full repack / rekey operation that packs only reachable objects from the
// local repository and squashes the backend chain under a lease push.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

// consolidate merges the victim packs into one and rewrites plan in place:
// the new pack carries Replaces so up-to-date clients skip the download,
// and the resulting push becomes a squash.
func (e *Engine) consolidate(cur *RemoteState, plan *pushPlan, victims []manifest.Pack) error {
	scratch, err := os.MkdirTemp(e.St.TmpDir(), "scratch-")
	if err != nil {
		return fmt.Errorf("create consolidation scratch dir: %w", err)
	}
	defer os.RemoveAll(scratch)
	scratchGit := filepath.Join(scratch, "odb.git")
	if _, _, err := e.G.Run(gitx.Opts{Scrub: true}, "init", "--bare", "--quiet", scratchGit); err != nil {
		return cloakerr.New(cloakerr.LocalGit, "init scratch repo", err)
	}

	victimIDs, canMark, err := e.indexVictims(scratchGit, cur, plan, victims)
	if err != nil {
		return err
	}
	pw, err := e.packConsolidated(scratchGit)
	if err != nil {
		return err
	}
	if err := e.applyConsolidation(plan, pw, victimIDs, canMark); err != nil {
		return err
	}
	e.Log.Info("consolidated packs", "victims", len(victimIDs),
		"merged_bytes", pw.Size(), "live_packs", len(plan.man.Packs))
	return nil
}

// indexVictims indexes each victim pack into the scratch repository and reports
// whether every victim was already applied locally (canMark): the merged pack
// can be marked applied only when all the packs folded into it were. The
// not-yet-pushed pack (plan.packID) is sourced from disk; the rest download.
func (e *Engine) indexVictims(scratchGit string, cur *RemoteState, plan *pushPlan, victims []manifest.Pack) ([]string, bool, error) {
	applied, err := e.St.AppliedSet()
	if err != nil {
		return nil, false, err
	}
	victimIDs, canMark := canMarkConsolidated(victims, plan.packID, applied)
	for _, v := range victims {
		localPath := ""
		if v.ID == plan.packID {
			localPath = plan.packPath
		}
		if err := e.indexPackInto(scratchGit, cur.Head, v, localPath); err != nil {
			return nil, false, err
		}
	}
	return victimIDs, canMark, nil
}

// canMarkConsolidated returns the victim ids in order and reports whether the
// merged consolidation pack may be recorded as already applied. The merged
// pack's objects are all guaranteed present locally only when every victim is
// either the not-yet-pushed pack (notYetPushedID, sourced from disk and packed
// from objects the local repo already holds) or was already applied; otherwise
// some victim's objects were never indexed locally, so the merged pack must NOT
// be marked applied or a future fetch would skip downloading it (packSkippable
// treats an applied pack as covered) and those objects would stay missing
// forever, since the applied set is never re-examined. Pure -- the per-victim
// scratch indexing stays in indexVictims -- so the gate is testable without a
// git host.
func canMarkConsolidated(victims []manifest.Pack, notYetPushedID string, applied map[string]bool) (victimIDs []string, canMark bool) {
	victimIDs = make([]string, 0, len(victims))
	canMark = true
	for _, v := range victims {
		victimIDs = append(victimIDs, v.ID)
		if v.ID != notYetPushedID && !applied[v.ID] {
			canMark = false
		}
	}
	return victimIDs, canMark
}

// packConsolidated enumerates every object now in the scratch repository and
// writes them all into a single freshly encrypted pack.
func (e *Engine) packConsolidated(scratchGit string) (*agecrypt.PackWriter, error) {
	objects, _, err := e.G.Run(gitx.Opts{GitDir: scratchGit},
		"cat-file", "--batch-all-objects", "--batch-check=%(objectname)")
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "enumerate scratch objects", err)
	}
	pw, err := agecrypt.NewPackWriter(e.St.TmpDir(), e.Key)
	if err != nil {
		return nil, err
	}
	if err := e.streamPack(pw, gitx.Opts{GitDir: scratchGit,
		Stdin: strings.NewReader(objects), Stdout: pw},
		"pack consolidated objects", "finalize consolidated pack",
		"--stdout", "--delta-base-offset"); err != nil {
		return nil, err
	}
	return pw, nil
}

// applyConsolidation rewrites plan in place to replace the victim packs with
// the single merged pack pw: it drops the victims from the live set, appends
// the new pack carrying their ids as Replaces, removes the superseded local
// ciphertext, and re-validates the resulting manifest.
func (e *Engine) applyConsolidation(plan *pushPlan, pw *agecrypt.PackWriter, victimIDs []string, canMark bool) error {
	if plan.packPath != "" {
		_ = os.Remove(plan.packPath)
	}
	plan.man.Packs = consolidatedPacks(plan.man.Packs, victimIDs, pw.ID(), pw.Size())
	plan.packID, plan.packPath, plan.packSize = pw.ID(), pw.Path(), pw.Size()
	plan.markApplied = canMark
	if err := plan.man.Validate(); err != nil {
		return fmt.Errorf("consolidated manifest invalid (bug): %w", err)
	}
	return nil
}

// consolidatedPacks computes the live pack set for a geometric consolidation:
// it drops the victim packs from packs and appends the single merged pack
// (identified by id and ciphertext size) carrying every victim id as Replaces,
// so a client that already applied the folded packs skips re-downloading the
// merged one (packSkippable). Non-victim packs are retained in their original
// order and the merged pack is appended last. Pure (the os.Remove of the
// superseded local ciphertext stays in applyConsolidation), so the pack-set
// transformation is testable without a git host or a real PackWriter.
func consolidatedPacks(packs []manifest.Pack, victimIDs []string, id string, size int64) []manifest.Pack {
	inVictims := map[string]bool{}
	for _, vid := range victimIDs {
		inVictims[vid] = true
	}
	var liveSurvivors []manifest.Pack
	for _, p := range packs {
		if !inVictims[p.ID] {
			liveSurvivors = append(liveSurvivors, p)
		}
	}
	return append(liveSurvivors,
		manifest.Pack{ID: id, Size: size, Replaces: victimIDs})
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
		if err := e.downloadVerifyPack(head, ctPath, p); err != nil {
			return err
		}
	}
	ct, err := os.Open(ctPath)
	if err != nil {
		return fmt.Errorf("open pack ciphertext scratch file %q: %w", ctPath, err)
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

// repackAttempt is the outcome of one FullRepack iteration. When done is true
// the repack resolved and FullRepack returns (state, nil); when done is false a
// compare-and-swap was lost and state is the re-fetched remote the next attempt
// retries against. state is read only on those paths, mirroring pushAttempt.
type repackAttempt struct {
	state *RemoteState
	done  bool
}

// FullRepack rebuilds the remote as a single pack of objects reachable from
// the manifest refs (sourced from the local repository), optionally under a
// new master key (rekey), and squashes the backend chain with a lease push.
// It owns only the retry loop: each iteration delegates one attempt to
// repackOnce and, on a lost compare-and-swap, retries against the re-fetched
// state until PushRetries is exhausted.
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
		a, err := e.repackOnce(cur, key, newKey != nil, attempt)
		if err != nil {
			return nil, err
		}
		if a.done {
			return a.state, nil
		}
		cur = a.state
	}
	return nil, cloakerr.Newfh(cloakerr.CASExhausted, "repack",
		"another client keeps winning the push race; wait for other syncs to settle and re-run `git cloak repack`/`rekey`, or raise `git config cloak.pushRetries`",
		"lost the compare-and-swap race %d times in a row", e.Cfg.PushRetries+1)
}

// repackOnce runs a single full-repack attempt against cur under key: it
// re-applies the remote, packs every reachable object into one squashing pack,
// builds the re-rooted backend commit, and lease-pushes it. It reports done=true
// with the new remote state when the push is accepted, or done=false with the
// re-fetched state when the compare-and-swap is lost so the caller can retry.
func (e *Engine) repackOnce(cur *RemoteState, key keystore.Key, rekeyed bool, attempt int) (repackAttempt, error) {
	pw, err := e.repackPack(cur, key)
	if err != nil {
		return repackAttempt{}, err
	}
	man := repackManifest(cur, pw.ID(), pw.Size())
	res, bc, err := e.commitAndPushRepack(cur, man, pw, key)
	if err != nil {
		return repackAttempt{}, err
	}
	switch res {
	case backend.PushOK:
		return e.acceptRepack(man, bc, rekeyed)
	case backend.PushCASLost:
		return e.retryRepackAfterCASLost(attempt)
	}
	return repackAttempt{state: cur, done: false}, nil
}

// acceptRepack records a backend-accepted full repack (the PushOK arm of
// repackOnce): it persists the pin/repo-id/applied state, logs acceptance, and
// returns the resolved attempt carrying the new remote state. The merged pack is
// always marked applied (its objects came from the local repository).
func (e *Engine) acceptRepack(man *manifest.Manifest, bc builtCommit, rekeyed bool) (repackAttempt, error) {
	if err := e.persistPushed(man.Generation, bc.manifestHash, man.RepoID, man.Packs[0].ID, true); err != nil {
		return repackAttempt{}, err
	}
	e.Log.Info("full repack pushed", "generation", man.Generation,
		"pack_bytes", man.Packs[0].Size, "rekeyed", rekeyed)
	return repackAttempt{state: &RemoteState{Head: bc.commit, Manifest: man, ManifestHash: bc.manifestHash}, done: true}, nil
}

// retryRepackAfterCASLost handles the PushCASLost arm of repackOnce: it
// re-fetches the remote state and returns a not-done attempt so the FullRepack
// loop retries the next attempt against it. (Info, not Warn like Push: a repack
// is an explicit maintenance operation, so a lost race is routine progress.)
func (e *Engine) retryRepackAfterCASLost(attempt int) (repackAttempt, error) {
	e.Log.Info("repack lost compare-and-swap; re-fetching and retrying", "attempt", attempt)
	next, err := e.LoadRemoteState()
	if err != nil {
		return repackAttempt{}, err
	}
	return repackAttempt{state: next, done: false}, nil
}

// repackPack re-applies the remote (FetchApply) and packs every object
// reachable from the manifest refs, sourced from the local repository, into a
// single freshly encrypted pack under key. FetchApply runs inside each attempt
// because after a lost compare-and-swap the reloaded manifest may reference
// objects a concurrent push added, which the local repository must hold before
// pack-objects can want them. streamPack aborts pw on any error, so a failed
// pack leaves no temp file behind.
func (e *Engine) repackPack(cur *RemoteState, key keystore.Key) (*agecrypt.PackWriter, error) {
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
	if err := e.streamPack(pw, gitx.Opts{GitDir: e.LocalGitDir,
		Stdin: strings.NewReader(wants.String()), Stdout: pw},
		"pack reachable objects", "finalize repack pack",
		"--revs", "--stdout", "--delta-base-offset"); err != nil {
		return nil, err
	}
	return pw, nil
}

// repackManifest builds the next-generation manifest for a full repack: a clone
// of cur's manifest with the generation bumped and its pack set replaced by the
// single merged pack (identified by id and ciphertext size), carrying every
// prior pack id as Replaces. Taking the merged pack's id/size directly (rather
// than the *agecrypt.PackWriter) keeps this a pure manifest-construction
// function the caller passes pw.ID()/pw.Size() into.
func repackManifest(cur *RemoteState, id string, size int64) *manifest.Manifest {
	oldIDs := make([]string, 0, len(cur.Manifest.Packs))
	for _, p := range cur.Manifest.Packs {
		oldIDs = append(oldIDs, p.ID)
	}
	man := cur.Manifest.Clone()
	man.Generation++
	man.Packs = []manifest.Pack{{ID: id, Size: size, Replaces: oldIDs}}
	return man
}

// commitAndPushRepack assembles the re-rooted backend commit for man (no parent
// chain; a repack squashes the history) and lease-pushes it against cur.Head.
// pw's temp ciphertext is removed once the commit is built regardless of
// outcome. The returned PushResult is meaningful only when err is nil.
func (e *Engine) commitAndPushRepack(cur *RemoteState, man *manifest.Manifest, pw *agecrypt.PackWriter, key keystore.Key) (backend.PushResult, builtCommit, error) {
	bc, err := e.buildBackendCommit(commitInput{
		man: man, packID: pw.ID(), packPath: pw.Path(),
		blobSource: "", parent: "", key: key,
	})
	_ = os.Remove(pw.Path())
	if err != nil {
		return 0, builtCommit{}, err
	}
	res, err := e.Be.PushLease(bc.commit, cur.Head)
	return res, bc, err
}
