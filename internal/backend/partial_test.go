// Partial-mirror fallback: cloak fetches with blob:limit so the manifest
// inlines while large packs stay lazy. If a host rejects filtering the
// mirror must drop to full fetches and keep working. NOTE: local git
// transport only *warns* on a rejected --filter (it does not error), so
// the error-driven auto-fallback inside Fetch cannot be reproduced with a
// local bare repo; these tests instead pin the disablePartial mechanism
// directly and prove a non-filtering host still yields all data.
package backend

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

// newHostNoFilter is a bare host that does NOT advertise filter support.
func newHostNoFilter(t *testing.T, g *gitx.G) string {
	t.Helper()
	host := filepath.Join(t.TempDir(), "host-nofilter.git")
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--bare", "--initial-branch", "cloak", host); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: host}, "config", "uploadpack.allowfilter", "false"); err != nil {
		t.Fatal(err)
	}
	return host
}

func TestDisablePartialUnsetsConfig(t *testing.T) {
	g, host := newHost(t)
	b := openMirror(t, g, host)
	if !b.partial {
		t.Fatal("mirror did not start partial")
	}
	// Both promisor knobs must be set initially.
	for _, key := range []string{"remote.origin.promisor", "remote.origin.partialclonefilter"} {
		if v, err := b.g.Out(gitx.Opts{GitDir: b.gitDir}, "config", "--get", key); err != nil || v == "" {
			t.Fatalf("expected %s set initially, got %q (err %v)", key, v, err)
		}
	}

	b.disablePartial()

	if b.partial {
		t.Fatal("partial flag still set after disablePartial")
	}
	for _, key := range []string{"remote.origin.promisor", "remote.origin.partialclonefilter"} {
		if v, err := b.g.Out(gitx.Opts{GitDir: b.gitDir}, "config", "--get", key); err == nil && v != "" {
			t.Fatalf("%s still configured after disablePartial: %q", key, v)
		}
	}
}

func TestFetchWorksAgainstNonFilteringHost(t *testing.T) {
	g := gitx.New(slog.New(slog.DiscardHandler))
	host := newHostNoFilter(t, g)

	a := openMirror(t, g, host)
	commit, _ := seedCommit(t, a, "manifest-ct", "pack-ct", 1)
	if res, err := a.PushFF(commit); err != nil || res != PushOK {
		t.Fatalf("seed push = (%v, %v)", res, err)
	}

	// A fresh partial mirror against a host that does not honor filtering
	// must still fetch the full state and read both blobs back intact.
	b := openMirror(t, g, host)
	head, empty, err := b.Fetch()
	if err != nil {
		t.Fatalf("fetch against non-filtering host failed: %v", err)
	}
	if empty || head != commit {
		t.Fatalf("fetch = (%q, empty=%v), want (%q, false)", head, empty, commit)
	}
	ct, err := b.ReadBlobBytes(head, "manifest.age")
	if err != nil {
		t.Fatal(err)
	}
	if string(ct) != "manifest-ct" {
		t.Fatalf("manifest blob = %q", ct)
	}

	// After an explicit fallback the mirror is still fully functional.
	b.disablePartial()
	head2, _, err := b.Fetch()
	if err != nil || head2 != commit {
		t.Fatalf("post-fallback fetch = (%q, %v)", head2, err)
	}
	if names := mustLsTree(t, b, head2); len(names) == 0 {
		t.Fatal("post-fallback tree is empty")
	}
}

func mustLsTree(t *testing.T, b *Backend, commit string) []string {
	t.Helper()
	out, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir}, "ls-tree", "-r", "--name-only", commit)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l != "" {
			names = append(names, l)
		}
	}
	return names
}
