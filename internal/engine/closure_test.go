// Tests for HasObjectClosure, the gate that keeps FetchApply's no-download
// shortcut from poisoning the applied set (CR-002): a ref tip can be present
// locally while its history is not, and only a full-closure check may license
// skipping a pack download.
package engine

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

func gitInDir(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newEngine(gitDir string) *Engine {
	return &Engine{
		G:           gitx.New(slog.New(slog.NewTextHandler(io.Discard, nil))),
		LocalGitDir: gitDir,
	}
}

func TestHasObjectClosure(t *testing.T) {
	// repoA holds a complete two-commit history.
	a := t.TempDir()
	gitInDir(t, a, "init", "-q")
	gitInDir(t, a, "commit", "-q", "--allow-empty", "-m", "c1")
	gitInDir(t, a, "commit", "-q", "--allow-empty", "-m", "c2")
	tip := gitInDir(t, a, "rev-parse", "HEAD")
	parent := gitInDir(t, a, "rev-parse", "HEAD^")
	aGit := filepath.Join(a, ".git")

	if !newEngine(aGit).HasObjectClosure([]string{tip}) {
		t.Fatal("complete history: HasObjectClosure should be true")
	}

	// repoB receives ONLY the tip commit object, not its parent: the tip is
	// present but the history is incomplete (the CR-002 condition).
	b := t.TempDir()
	gitInDir(t, b, "init", "-q")
	bGit := filepath.Join(b, ".git")
	copyLooseObject(t, aGit, bGit, tip)

	eng := newEngine(bGit)
	if !eng.HaveObject(tip) {
		t.Fatal("setup: tip object should be present in repoB")
	}
	if eng.HaveObject(parent) {
		t.Fatal("setup: parent object should be ABSENT in repoB")
	}
	if eng.HasObjectClosure([]string{tip}) {
		t.Fatal("incomplete history: HasObjectClosure must be false when the tip is present but ancestors are missing")
	}
}

// copyLooseObject copies a single loose object file between object stores,
// reproducing a tip-present-but-history-missing repository.
func copyLooseObject(t *testing.T, srcGit, dstGit, oid string) {
	t.Helper()
	rel := filepath.Join("objects", oid[:2], oid[2:])
	data, err := os.ReadFile(filepath.Join(srcGit, rel))
	if err != nil {
		t.Fatalf("read loose object %s: %v (it may have been packed)", oid, err)
	}
	dir := filepath.Join(dstGit, "objects", oid[:2])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, oid[2:]), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
