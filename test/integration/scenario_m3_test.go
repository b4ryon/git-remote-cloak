// M3 scenarios from the DESIGN.md testing plan: 0 (full round trip via
// push), 1 (incremental pack growth), 2 (deterministic concurrent-push
// race via the hold hook), 3 (same-ref conflict surfaces as a normal
// non-fast-forward), and 9 (mid-connection stale rejection via a delaying
// pre-receive hook).
package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

// pushSetup creates a host plus client A with one pushed commit on main.
func pushSetup(t *testing.T) (*harness.Host, string, *harness.Client) {
	t.Helper()
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	a.WriteFile("readme.md", "initial content\n")
	a.Commit("c0")
	a.MustGit("remote", "add", "origin", "cloak::"+host.Dir)
	a.MustGit("push", "-u", "origin", "main")
	return host, key, a
}

func TestScenario0RoundTrip(t *testing.T) {
	host, key, a := pushSetup(t)

	a.WriteFile("second.md", "second file\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")

	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)
	if b.HeadOID() != a.HeadOID() {
		t.Fatalf("clone HEAD %s != source %s", b.HeadOID(), a.HeadOID())
	}

	// Reverse direction: B pushes, A pulls.
	b.WriteFile("third.md", "from b\n")
	b.Commit("c2")
	b.MustGit("push", "origin", "main")
	a.MustGit("pull", "origin", "main")
	if a.HeadOID() != b.HeadOID() {
		t.Fatalf("after pull, A HEAD %s != B HEAD %s", a.HeadOID(), b.HeadOID())
	}
	if got, err := os.ReadFile(filepath.Join(a.Dir, "third.md")); err != nil || string(got) != "from b\n" {
		t.Fatalf("pulled content wrong: %q err=%v", got, err)
	}
	for _, path := range host.LsTreeR("cloak") {
		if !hostPathRe.MatchString(path) {
			t.Fatalf("host tree leaks a non-opaque path: %q", path)
		}
	}
}

func TestScenario1IncrementalPush(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	var big strings.Builder
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&big, "line %d: %d words of varied content %x\n", i, i*i, i*7919)
	}
	a.WriteFile("big.md", big.String())
	a.Commit("c0")
	a.MustGit("remote", "add", "origin", "cloak::"+host.Dir)
	a.MustGit("push", "-u", "origin", "main")

	a.WriteFile("tiny.md", "one small edit\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")

	sizes := hostPackSizes(t, host)
	if len(sizes) != 2 {
		t.Fatalf("pack count = %d, want 2 (incremental)", len(sizes))
	}
	small, large := sizes[0], sizes[1]
	if small > large {
		small, large = large, small
	}
	if small >= large {
		t.Fatalf("second push was not incremental: pack sizes %v", sizes)
	}
	if small > 4096 {
		t.Fatalf("incremental pack unexpectedly large: %d bytes", small)
	}
}

// hostPackSizes returns ciphertext blob sizes under packs/ on the host.
func hostPackSizes(t *testing.T, host *harness.Host) []int64 {
	t.Helper()
	var sizes []int64
	out := host.Git("ls-tree", "-r", "-l", "cloak")
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "packs/") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			t.Fatalf("unexpected ls-tree line: %q", line)
		}
		n, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			t.Fatalf("size parse %q: %v", line, err)
		}
		sizes = append(sizes, n)
	}
	return sizes
}

func TestScenario2ConcurrentPushRace(t *testing.T) {
	host, key, a := pushSetup(t)
	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)

	a.MustGit("checkout", "-q", "-b", "branch-a")
	a.WriteFile("a.md", "from a\n")
	a.Commit("on branch-a")
	b.MustGit("checkout", "-q", "-b", "branch-b")
	b.WriteFile("b.md", "from b\n")
	b.Commit("on branch-b")

	hold := t.TempDir()
	type pushOut struct {
		stderr string
		err    error
	}
	done := make(chan pushOut, 1)
	go func() {
		_, stderr, err := a.GitEnv([]string{"CLOAK_TEST_HOLD_BEFORE_PUSH=" + hold},
			"push", "origin", "branch-a")
		done <- pushOut{stderr, err}
	}()
	waitForFile(t, filepath.Join(hold, "waiting"), 15*time.Second)

	b.MustGit("push", "origin", "branch-b")

	if err := os.WriteFile(filepath.Join(hold, "release"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("racing push did not converge: %v\nstderr: %s", res.err, res.stderr)
	}
	if !strings.Contains(a.DebugLog(), "compare-and-swap lost") {
		t.Fatal("race did not exercise the CAS retry path (hold hook ineffective?)")
	}

	c := harness.NewClient(t, "c", key)
	c.MustClone(host.Dir)
	if got, want := c.MustGit("rev-parse", "origin/branch-a"), a.HeadOID(); got != want {
		t.Fatalf("branch-a lost in race: %s != %s", got, want)
	}
	if got, want := c.MustGit("rev-parse", "origin/branch-b"), b.HeadOID(); got != want {
		t.Fatalf("branch-b lost in race: %s != %s", got, want)
	}
}

func TestScenario3RefConflict(t *testing.T) {
	host, key, a := pushSetup(t)
	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)

	a.WriteFile("a.md", "diverge a\n")
	a.Commit("diverge a")
	b.WriteFile("b.md", "diverge b\n")
	b.Commit("diverge b")

	b.MustGit("push", "origin", "main")
	_, stderr, err := a.Git("push", "origin", "main")
	if err == nil {
		t.Fatal("divergent push succeeded; expected per-ref rejection")
	}
	if !strings.Contains(stderr, "non-fast-forward") && !strings.Contains(stderr, "rejected") {
		t.Fatalf("rejection not surfaced as non-fast-forward: %s", stderr)
	}

	a.MustGit("pull", "--rebase", "origin", "main")
	a.MustGit("push", "origin", "main")
	b.MustGit("pull", "origin", "main")
	if a.HeadOID() != b.HeadOID() {
		t.Fatalf("did not converge after rebase: %s != %s", a.HeadOID(), b.HeadOID())
	}
}

func TestScenario9MidConnectionStaleRejection(t *testing.T) {
	host, key, a := pushSetup(t)
	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)

	a.WriteFile("a2.md", "second from a\n")
	a.Commit("c-a2")
	b.MustGit("checkout", "-q", "-b", "branch-b")
	b.WriteFile("b.md", "from b\n")
	b.Commit("c-b")

	// The hook delays only the FIRST push past its advertisement, opening
	// the mid-connection window for B's push to land; receive-pack must
	// then reject A's update server-side (reference changed since
	// discovery), and the helper retries cleanly.
	marker := filepath.Join(t.TempDir(), "hook-fired")
	host.InstallPreReceive(fmt.Sprintf("#!/bin/sh\nif [ ! -f %q ]; then\n  touch %q\n  sleep 3\nfi\nexit 0\n", marker, marker))
	defer host.RemovePreReceive()

	type pushOut struct {
		stderr string
		err    error
	}
	done := make(chan pushOut, 1)
	go func() {
		_, stderr, err := a.Git("push", "origin", "main")
		done <- pushOut{stderr, err}
	}()
	waitForFile(t, marker, 15*time.Second)
	b.MustGit("push", "origin", "branch-b")

	res := <-done
	if res.err != nil {
		t.Fatalf("push did not recover from mid-connection race: %v\nstderr: %s\nlog: %s",
			res.err, res.stderr, a.DebugLog())
	}
	if !strings.Contains(a.DebugLog(), "compare-and-swap lost") {
		t.Fatalf("server-side stale rejection not exercised; hook timing failed\nlog: %s", a.DebugLog())
	}
	// Both updates must survive the race (chain length is not asserted:
	// geometric consolidation may legitimately squash it).
	c := harness.NewClient(t, "c", key)
	c.MustClone(host.Dir)
	if got, want := c.MustGit("rev-parse", "origin/main"), a.HeadOID(); got != want {
		t.Fatalf("main lost in mid-connection race: %s != %s", got, want)
	}
	if got, want := c.MustGit("rev-parse", "origin/branch-b"), b.HeadOID(); got != want {
		t.Fatalf("branch-b lost in mid-connection race: %s != %s", got, want)
	}
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
