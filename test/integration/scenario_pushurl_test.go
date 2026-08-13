// Issue #3 scenarios: a remote with multiple push URLs. Each push URL is an
// independent cloak backend with its own local state (mirror, rollback pin,
// repo-id pin, applied set), so one `git push` replicates to every URL
// without the shared-pin rollback alarm the old remote-name keying raised on
// the second URL, and per-URL recovery commands address one backend without
// touching the others.
package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

// pushurlSetup wires a writer client whose origin fetches from hostA and
// pushes to BOTH hostA and hostB (the issue #3 configuration), with one
// commit pushed to each.
func pushurlSetup(t *testing.T) (hostA, hostB *harness.Host, a *harness.Client) {
	key := harness.NewKeyFile(t)
	hostA, hostB = harness.NewHost(t), harness.NewHost(t)
	a = harness.NewClient(t, "writer", key)
	a.InitRepo()
	a.AddOrigin(hostA.Dir)
	a.MustGit("config", "--add", "remote.origin.pushurl", "cloak::"+hostA.Dir)
	a.MustGit("config", "--add", "remote.origin.pushurl", "cloak::"+hostB.Dir)
	a.WriteFile("note.md", "v1\n")
	a.Commit("c0")
	a.MustGit("push", "origin", "main")
	return hostA, hostB, a
}

func TestScenarioPushurlReplication(t *testing.T) {
	hostA, hostB, a := pushurlSetup(t)

	// Both hosts hold a backend branch after ONE push (the old shared-state
	// keying alarmed on hostB before ever creating it).
	hostA.Git("rev-parse", "--verify", "refs/heads/cloak")
	hostB.Git("rev-parse", "--verify", "refs/heads/cloak")

	// Follow-up pushes keep working: the original failure mode was the second
	// helper invocation tripping over the first one's generation pin.
	a.WriteFile("note.md", "v2\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")

	// The two backends keep separate state dirs: the fetch URL under the
	// remote name, the extra push URL under a url-hash dir.
	if _, err := os.Stat(filepath.Join(a.Dir, ".git", "cloak", "origin")); err != nil {
		t.Fatalf("missing name-keyed state dir: %v", err)
	}
	urlDirs, err := filepath.Glob(filepath.Join(a.Dir, ".git", "cloak", "url-*"))
	if err != nil || len(urlDirs) != 1 {
		t.Fatalf("want exactly one url-hash state dir, got %v (err %v)", urlDirs, err)
	}

	// status --url reads the second backend's state.
	out := a.MustCloak("status", "--remote", "origin", "--url", "cloak::"+hostB.Dir)
	if !strings.Contains(out, "URL:        cloak::"+hostB.Dir) {
		t.Fatalf("status --url does not name the selected backend:\n%s", out)
	}
	if !strings.Contains(out, "up to date with the remote") {
		t.Fatalf("second backend not pinned up to date:\n%s", out)
	}
}

// A fresh clone from EITHER push URL converges on the same history: the two
// backends are fully independent encrypted mirrors of the same repository.
func TestScenarioPushurlClonesConverge(t *testing.T) {
	key := harness.NewKeyFile(t)
	hostA, hostB := harness.NewHost(t), harness.NewHost(t)
	a := harness.NewClient(t, "writer", key)
	a.InitRepo()
	a.AddOrigin(hostA.Dir)
	a.MustGit("config", "--add", "remote.origin.pushurl", "cloak::"+hostA.Dir)
	a.MustGit("config", "--add", "remote.origin.pushurl", "cloak::"+hostB.Dir)
	a.WriteFile("note.md", "v1\n")
	a.Commit("c0")
	a.MustGit("push", "origin", "main")

	rA := harness.NewClient(t, "readerA", key)
	rA.MustClone(hostA.Dir)
	rB := harness.NewClient(t, "readerB", key)
	rB.MustClone(hostB.Dir)
	if rA.HeadOID() != a.HeadOID() || rB.HeadOID() != a.HeadOID() {
		t.Fatalf("clones diverge: writer %s, fromA %s, fromB %s",
			a.HeadOID(), rA.HeadOID(), rB.HeadOID())
	}
}

// Wiping ONE push URL's backend alarms only that URL, the alarm names the
// --url selector that reaches it, and accept-rollback --url recovers that
// backend while the other URL's pin stays untouched.
func TestScenarioPushurlRollbackIsolated(t *testing.T) {
	_, hostB, a := pushurlSetup(t)

	// Host B wipes its backend branch (rollback-to-empty).
	hostB.Git("update-ref", "-d", "refs/heads/cloak")

	_, stderr, err := a.Git("push", "origin", "main")
	if err == nil {
		t.Fatal("push succeeded against a wiped push URL")
	}
	if !strings.Contains(stderr, "ROLLBACK ALARM") {
		t.Fatalf("wiped push URL not reported as a rollback alarm:\n%s", stderr)
	}
	if !strings.Contains(stderr, "accept-rollback --url cloak::"+hostB.Dir) {
		t.Fatalf("alarm does not print the --url selector for the wiped backend:\n%s", stderr)
	}

	// accept-rollback for that URL only (non-interactive: presence skipped).
	out, errb, err := a.Cloak("accept-rollback", "--remote", "origin", "--url", "cloak::"+hostB.Dir)
	if err != nil {
		t.Fatalf("accept-rollback --url failed: %v\n%s", err, errb)
	}
	if !strings.Contains(out, "Accepted") {
		t.Fatalf("accept-rollback --url output: %q", out)
	}

	// The next push recreates B's backend; A's own pin was never touched.
	a.MustGit("push", "origin", "main")
	hostB.Git("rev-parse", "--verify", "refs/heads/cloak")
	out = a.MustCloak("status", "--remote", "origin")
	if !strings.Contains(out, "up to date with the remote") {
		t.Fatalf("fetch-URL backend disturbed by the per-URL recovery:\n%s", out)
	}
}
