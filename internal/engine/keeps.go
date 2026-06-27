// The keep-reaping half of the engine's fetch hygiene: removing cloak's own
// leftover pack .keep lock files. git's remote-helper fetch protocol records
// only one pack lockfile per fetch (transport-helper.c fetch_with_fetch keeps
// the first "lock" line and warns "<helper> also locked ..." on the rest), so a
// fetch that applies several packs (notably a clone) leaves git unable to clean
// all but one .keep; the orphans then pin those packs against gc/repack forever.
// ReapOrphanKeeps removes them on a later session, fail-safe by construction:
// only cloak's own ("cloak"-tagged) keeps are touched, and only once every
// object in the kept pack is reachable from refs, so a concurrent gc can never
// prune a not-yet-wired fetch's objects. It changes no on-disk/on-wire format,
// no crypto, and no fetch/push behavior; a .keep is purely a local git artifact.
package engine

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

// keepMessage is the marker cloak writes into every pack .keep it creates (git
// index-pack --keep=cloak in indexPackFile). ReapOrphanKeeps removes only .keep
// files carrying exactly this marker, so a user's manual .keep or another tool's
// is never touched.
const keepMessage = "cloak"

// isLowerHex reports whether s is exactly n lowercase hex digits ([0-9a-f]) -
// the shape of a git object id (40 chars, sha1; non-sha1 repos are rejected at
// setup) as it appears in show-index / rev-list output. Exact non-regex
// equivalent of `^[0-9a-f]{n}$` (lowercase only, whole string).
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ReapOrphanKeeps removes cloak's leftover pack .keep lock files whose pack
// objects are now reachable from refs. It is best-effort session hygiene: it
// never returns an error, never blocks the session, and fails safe by leaving
// in place any .keep it cannot prove safe to remove. The caller invokes it once
// per session, under the per-remote state lock and before this session's own
// fetch/push runs, so it only ever sees orphans created by EARLIER, completed
// invocations (a pack this session is about to create does not exist yet, and a
// half-applied pack from a crashed fetch is not yet reachable, so both are left
// alone).
func (e *Engine) ReapOrphanKeeps() {
	ours := e.cloakKeeps()
	if len(ours) == 0 {
		return
	}
	reachable, ok := e.reachableObjects()
	if !ok {
		// Without the reachable set, no removal is provably safe: leave them all.
		e.Log.Warn("orphan keep reap skipped: reachable object set unavailable")
		return
	}
	removed := 0
	for _, k := range ours {
		if e.keepIsRedundant(k, reachable) && e.removeKeep(k) {
			removed++
		}
	}
	if removed > 0 {
		e.Log.Info("reaped orphan pack keeps", "removed", removed, "candidates", len(ours))
	}
}

// cloakKeeps returns the paths of pack .keep files in the local object store
// that carry cloak's keep marker. A glob/read error or a non-cloak marker
// excludes the file (fail safe: never act on a keep we did not create or cannot
// read).
func (e *Engine) cloakKeeps() []string {
	matches, err := filepath.Glob(filepath.Join(e.LocalGitDir, "objects", "pack", "pack-*.keep"))
	if err != nil {
		return nil
	}
	var ours []string
	for _, k := range matches {
		if isCloakKeep(k) {
			ours = append(ours, k)
		}
	}
	return ours
}

// isCloakKeep reports whether the .keep file at path carries cloak's keep
// marker (the message git index-pack --keep=cloak writes). Any read error
// returns false so an unreadable keep is left untouched.
func isCloakKeep(path string) bool {
	b, err := os.ReadFile(path) // #nosec G304 -- path is a Glob match under LocalGitDir/objects/pack; no caller- or remote-controlled component
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == keepMessage
}

// reachableObjects returns the set of object ids reachable from all refs in the
// local repository, with ok=false when git could not enumerate them.
// Reachability is taken from refs only (git rev-list --objects --all): that is a
// SUBSET of what git gc treats as reachable (which also honors reflogs, the
// index, and other roots), so a keep is removed only when its objects are
// guaranteed to survive gc. An object reachable solely via a non-ref root is
// conservatively treated as unreachable here, which only ever leaves a keep in
// place, never removes one unsafely.
func (e *Engine) reachableObjects() (map[string]bool, bool) {
	out, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir}, "rev-list", "--objects", "--all")
	if err != nil {
		return nil, false
	}
	set := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		// Each line is "<sha>" (commits) or "<sha> <path>" (trees/blobs); the id
		// is the first whitespace-delimited field.
		if id, _, _ := strings.Cut(strings.TrimSpace(line), " "); id != "" {
			set[id] = true
		}
	}
	return set, true
}

// keepIsRedundant reports whether the pack guarded by the .keep at keepPath has
// every one of its objects reachable from refs, so the keep no longer protects
// anything gc would otherwise prune and can be safely removed. It reads the
// pack's object ids from the matching .idx via git show-index and requires every
// one to be in reachable; any open/parse error, an empty object list, or a
// single unreachable object returns false (fail safe: keep the .keep).
func (e *Engine) keepIsRedundant(keepPath string, reachable map[string]bool) bool {
	idxPath := strings.TrimSuffix(keepPath, ".keep") + ".idx"
	idx, err := os.Open(idxPath) // #nosec G304 -- derived from a Glob match under LocalGitDir/objects/pack; no caller- or remote-controlled component
	if err != nil {
		return false
	}
	defer func() { _ = idx.Close() }()
	out, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir, Stdin: idx}, "show-index")
	if err != nil {
		return false
	}
	ids := packObjectIDs(out)
	if len(ids) == 0 {
		return false // not proof of safety; leave the keep
	}
	for _, id := range ids {
		if !reachable[id] {
			return false
		}
	}
	return true
}

// packObjectIDs extracts the object ids from git show-index output. Each line
// names one packed object as "<offset> <sha> (<crc>)"; the id is the 40-hex
// field. The format has varied across git versions (older output omits the
// crc), so the parse scans each line's fields for the hex id rather than fixing
// a column; lines with no hex id are skipped. Extracted as a pure function so it
// can be fuzzed without a git host.
func packObjectIDs(showIndexOut string) []string {
	var ids []string
	for _, line := range strings.Split(showIndexOut, "\n") {
		for _, f := range strings.Fields(line) {
			if isLowerHex(f, 40) {
				ids = append(ids, f)
				break
			}
		}
	}
	return ids
}

// removeKeep deletes the .keep file, returning whether it succeeded. A removal
// failure is logged and swallowed: a leftover keep is harmless (it only pins a
// pack against repacking), so reaping must never fail the session.
func (e *Engine) removeKeep(keepPath string) bool {
	if err := os.Remove(keepPath); err != nil {
		if !os.IsNotExist(err) {
			e.Log.Warn("removing orphan pack keep failed", "path", keepPath, "err", err)
		}
		return false
	}
	e.Log.Info("removed orphan pack keep", "path", keepPath)
	return true
}
