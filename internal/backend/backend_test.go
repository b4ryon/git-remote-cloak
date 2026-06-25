// Unit tests for the backend mirror that need no remote host: commit
// determinism (fixed identity, generation-derived dates) and the structure
// of built trees. Network behavior is covered by the integration suite.
package backend

import (
	"fmt"
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

// TestIsMissingPacksTree pins the sentinel detection PackBlobOIDs uses to tell a
// manifest-only commit (no packs/ subtree -> empty pack set) apart from a real
// ls-tree failure (surface it as LocalGit). The wrapped-error case is the
// regression guard: the prior direct type assertion (err.(*gitx.GitError))
// returned false for a wrapped GitError, which would have escalated a benign
// "no packs subtree" into a hard error and failed the push; errors.As sees
// through the wrap.
func TestIsMissingPacksTree(t *testing.T) {
	missing := &gitx.GitError{Args: []string{"ls-tree"}, Stderr: "fatal: Not a valid object name HEAD:packs"}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"bare missing subtree", missing, true},
		{"wrapped missing subtree", fmt.Errorf("list remote pack blobs: %w", missing), true},
		{"other git failure", &gitx.GitError{Args: []string{"ls-tree"}, Stderr: "fatal: not a git repository"}, false},
		{"non-git error", fmt.Errorf("some other error"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := isMissingPacksTree(c.err); got != c.want {
			t.Errorf("%s: isMissingPacksTree = %v, want %v", c.name, got, c.want)
		}
	}
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
