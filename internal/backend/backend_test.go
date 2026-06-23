// Unit tests for the backend mirror that need no remote host: commit
// determinism (fixed identity, generation-derived dates) and the structure
// of built trees. Network behavior is covered by the integration suite.
package backend

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

func open(t *testing.T) *Backend {
	t.Helper()
	lg := slog.New(slog.DiscardHandler)
	b, err := Open(gitx.New(lg), t.TempDir()+"/backend.git", "/nonexistent-host", "cloak", lg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildCommitDeterministic(t *testing.T) {
	b1, b2 := open(t), open(t)
	build := func(b *Backend) string {
		t.Helper()
		moid, err := b.HashObject(strings.NewReader("manifest-ciphertext"))
		if err != nil {
			t.Fatal(err)
		}
		poid, err := b.HashObject(strings.NewReader("pack-ciphertext"))
		if err != nil {
			t.Fatal(err)
		}
		id := strings.Repeat("ab", 32)
		commit, err := b.BuildCommit("", moid, map[string]string{id: poid}, 7)
		if err != nil {
			t.Fatal(err)
		}
		return commit
	}
	c1, c2 := build(b1), build(b2)
	if c1 != c2 {
		t.Fatalf("identical inputs produced different commits: %s vs %s (nondeterministic metadata)", c1, c2)
	}
}

func TestBuildCommitTreeShape(t *testing.T) {
	b := open(t)
	moid, _ := b.HashObject(strings.NewReader("m"))
	poid, _ := b.HashObject(strings.NewReader("p"))
	id := strings.Repeat("cd", 32)
	commit, err := b.BuildCommit("", moid, map[string]string{id: poid}, 1)
	if err != nil {
		t.Fatal(err)
	}
	out, err := b.g.Out(gitx.Opts{GitDir: b.gitDir}, "ls-tree", "-r", "--name-only", commit)
	if err != nil {
		t.Fatal(err)
	}
	want := "manifest.age\npacks/" + id + ".age"
	if out != want {
		t.Fatalf("tree = %q, want %q", out, want)
	}
	meta, err := b.g.Out(gitx.Opts{GitDir: b.gitDir}, "log", "-1", "--format=%an|%ae|%s", commit)
	if err != nil {
		t.Fatal(err)
	}
	if meta != "cloak|cloak@cloak|cloak" {
		t.Fatalf("commit metadata = %q", meta)
	}
}
