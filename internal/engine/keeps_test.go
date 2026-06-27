// Tests for ReapOrphanKeeps, the session-open hygiene that removes cloak's own
// leftover pack .keep lock files. git records only one pack lockfile per fetch,
// so a multi-pack fetch (a clone) leaves orphan .keep files; these tests pin the
// safety contract: a cloak-tagged keep is reaped ONLY when its pack's objects
// are reachable from refs, a cloak-tagged keep over unreachable objects is kept
// (a concurrent gc must not be able to prune a not-yet-wired fetch), and a keep
// cloak did not write (a different keep message) is never touched.
package engine

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitBin runs git capturing raw stdout (binary-safe, unlike gitInDir's
// CombinedOutput) with an optional stdin and an optional explicit GIT_DIR.
func gitBin(t *testing.T, dir, gitDir string, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
	)
	if gitDir != "" {
		cmd.Env = append(cmd.Env, "GIT_DIR="+gitDir)
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, errb.String())
	}
	return out.Bytes()
}

// makeKeptPack reproduces cloak's apply mechanism: it streams a pack out of git
// pack-objects (with --revs when revs is true, so items are rev-list args;
// otherwise items are bare object ids) and feeds it to git index-pack
// --keep=<keepMsg>, exactly as the engine does on fetch. It returns the path of
// the .keep file index-pack created.
func makeKeptPack(t *testing.T, repo, gitDir, keepMsg string, revs bool, items ...string) string {
	t.Helper()
	po := []string{"pack-objects", "--stdout", "--delta-base-offset"}
	if revs {
		po = append(po, "--revs")
	}
	pack := gitBin(t, repo, "", []byte(strings.Join(items, "\n")+"\n"), po...)
	out := gitBin(t, repo, gitDir, pack, "index-pack", "--stdin", "--keep="+keepMsg)
	keep := keepFileFromIndexPack(gitDir, string(out))
	if keep == "" {
		t.Fatalf("index-pack --keep=%q produced no keep line: %q", keepMsg, out)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("expected keep file %q to exist after index-pack: %v", keep, err)
	}
	return keep
}

func TestReapOrphanKeeps(t *testing.T) {
	repo := t.TempDir()
	gitInDir(t, repo, "init", "-q")
	// Two disjoint, fully reachable histories on separate branches (orphan root
	// commits with different files share no objects), plus one dangling blob
	// that no ref reaches.
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitInDir(t, repo, "add", "a.txt")
	gitInDir(t, repo, "commit", "-q", "-m", "c1")
	gitInDir(t, repo, "branch", "-M", "main")
	gitInDir(t, repo, "checkout", "-q", "--orphan", "other")
	gitInDir(t, repo, "rm", "-q", "-f", "a.txt")
	if err := os.WriteFile(filepath.Join(repo, "b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitInDir(t, repo, "add", "b.txt")
	gitInDir(t, repo, "commit", "-q", "-m", "c2")
	gitInDir(t, repo, "checkout", "-q", "main")

	gitDir := filepath.Join(repo, ".git")
	dangling := strings.TrimSpace(string(gitBin(t, repo, "", []byte("dangling\n"), "hash-object", "-w", "--stdin")))

	// reachableCloak: cloak's keep over objects reachable from refs/heads/main.
	// otherKeep:      a keep cloak did NOT write (different message), reachable.
	// unreachable:    cloak's keep over the dangling blob, reachable from no ref.
	reachableCloak := makeKeptPack(t, repo, gitDir, "cloak", true, "main")
	otherKeep := makeKeptPack(t, repo, gitDir, "user-manual", true, "other")
	unreachable := makeKeptPack(t, repo, gitDir, "cloak", false, dangling)

	// All three must be distinct packs, else the scenario is degenerate.
	if reachableCloak == otherKeep || reachableCloak == unreachable || otherKeep == unreachable {
		t.Fatalf("keeps are not distinct: %q %q %q", reachableCloak, otherKeep, unreachable)
	}

	eng := newEngine(gitDir)
	eng.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	eng.ReapOrphanKeeps()

	assertGone(t, "reachable cloak keep", reachableCloak)
	assertPresent(t, "non-cloak keep", otherKeep)
	assertPresent(t, "unreachable cloak keep", unreachable)

	// Idempotent and stable: a second pass removes nothing more and never errors.
	eng.ReapOrphanKeeps()
	assertGone(t, "reachable cloak keep (2nd pass)", reachableCloak)
	assertPresent(t, "non-cloak keep (2nd pass)", otherKeep)
	assertPresent(t, "unreachable cloak keep (2nd pass)", unreachable)
}

func assertGone(t *testing.T, what, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s: expected %q removed, stat err = %v", what, path, err)
	}
}

func assertPresent(t *testing.T, what, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s: expected %q kept, stat err = %v", what, path, err)
	}
}

// FuzzPackObjectIDs pins the show-index parser: every id it returns is a valid
// 40-hex object id, the parse is deterministic, and it never returns more ids
// than there are input lines (at most one id per line).
func FuzzPackObjectIDs(f *testing.F) {
	f.Add("0 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 (1a2b3c4d)")
	f.Add("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\n1234567890123456789012345678901234567890 x")
	f.Add("garbage\n\nno hex here (deadbeef)")
	f.Fuzz(func(t *testing.T, out string) {
		ids := packObjectIDs(out)
		for _, id := range ids {
			if !isLowerHex(id, 40) {
				t.Fatalf("returned non-oid %q", id)
			}
		}
		if again := packObjectIDs(out); strings.Join(again, ",") != strings.Join(ids, ",") {
			t.Fatalf("not deterministic: %v then %v", ids, again)
		}
		if n := strings.Count(out, "\n") + 1; len(ids) > n {
			t.Fatalf("more ids (%d) than lines (%d)", len(ids), n)
		}
	})
}
