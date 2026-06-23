// Unit tests for session construction without touching any remote:
// OpenLocal wiring (paths, config, key, state lock, backend mirror) and
// its rejection of non-cloak and unconfigured remotes.
package setup

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// initRepo creates a plain repository with a file-backend master key wired
// into cloak.keyref, and chdirs into it (OpenLocal resolves the repo from
// the working directory, as git does for helpers).
func initRepo(t *testing.T) (g *gitx.G, gitDir string) {
	t.Helper()
	g = gitx.New(slog.New(slog.DiscardHandler))
	dir := t.TempDir()
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--initial-branch", "main", dir); err != nil {
		t.Fatal(err)
	}
	// Resolve through git so symlinked temp dirs (macOS /var -> /private/var)
	// compare equal to the paths OpenLocal resolves the same way.
	gitDir, err := g.Out(gitx.Opts{Dir: dir}, "rev-parse", "--absolute-git-dir")
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "masterkey")
	k, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keystore.Save("file:"+keyPath, k); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "config", "cloak.keyRef", "file:"+keyPath); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	return g, gitDir
}

func TestOpenLocalWiresSession(t *testing.T) {
	_, gitDir := initRepo(t)
	host := filepath.Join(t.TempDir(), "host.git")

	s, err := OpenLocal("origin", "cloak::"+host, io.Discard, "cli")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if s.Eng == nil || s.St == nil || s.Log == nil || s.G == nil {
		t.Fatal("session has unwired fields")
	}
	if s.Eng.Key.IsZero() {
		t.Fatal("session key not loaded")
	}
	if s.Cfg.Branch != "cloak" {
		t.Fatalf("default branch = %q, want cloak", s.Cfg.Branch)
	}
	stateRoot := filepath.Join(gitDir, "cloak", "origin")
	if s.St.Root != stateRoot {
		t.Fatalf("state root = %q, want %q", s.St.Root, stateRoot)
	}
	if _, err := os.Stat(s.St.BackendGitDir()); err != nil {
		t.Fatalf("backend mirror not initialized: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, "lock")); err != nil {
		t.Fatalf("state lock file missing: %v", err)
	}
}

func TestOpenLocalRejectsNonCloakRemote(t *testing.T) {
	g, gitDir := initRepo(t)
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir},
		"remote", "add", "origin", "https://example.invalid/repo.git"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal("origin", "", io.Discard, "cli"); err == nil {
		t.Fatal("OpenLocal accepted a non-cloak:: remote")
	}
}

func TestOpenLocalRejectsUnknownRemote(t *testing.T) {
	initRepo(t)
	if _, err := OpenLocal("nosuch", "", io.Discard, "cli"); err == nil {
		t.Fatal("OpenLocal accepted a remote with no configured URL")
	}
}

// A backend URL using git's remote-helper syntax (ext::, fd::, nested cloak::)
// must be refused so a malicious cloak:: URL cannot reach git's
// arbitrary-command transports. Real transports and local paths must pass.
func TestOpenLocalTransportGuard(t *testing.T) {
	rejected := []string{
		"cloak::ext::sh -c 'touch pwned'",
		"cloak::fd::3",
		"cloak::cloak::" + filepath.Join(t.TempDir(), "nested.git"),
	}
	for _, url := range rejected {
		initRepo(t)
		if s, err := OpenLocal("origin", url, io.Discard, "cli"); err == nil {
			s.Close()
			t.Fatalf("OpenLocal accepted dangerous transport %q", url)
		}
	}
	accepted := []string{
		"cloak::" + filepath.Join(t.TempDir(), "bare.git"), // local path
		"cloak::file://" + filepath.Join(t.TempDir(), "f.git"),
		"cloak::ssh://git@example.invalid/r.git",
		"cloak::git@example.invalid:r.git", // scp-like SSH
		"cloak::https://example.invalid/r.git",
	}
	for _, url := range accepted {
		initRepo(t)
		s, err := OpenLocal("origin", url, io.Discard, "cli")
		if err != nil {
			t.Fatalf("OpenLocal rejected legitimate transport %q: %v", url, err)
		}
		s.Close()
	}
}
