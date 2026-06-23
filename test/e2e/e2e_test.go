// Live end-to-end tests against a real GitHub repository, exercising host
// quirks the hermetic harness cannot (real SSH transport, partial-clone
// filter support, server-side ref locking, background gc). Gated behind
// the e2e build tag AND CLOAK_E2E=1 so ordinary `make test` never touches
// the network. The target repo defaults to git@github.com:b4ryon/
// cloak-e2e-scratch.git (override with CLOAK_E2E_URL); each run uses a
// unique backend branch and deletes it afterward, so the repo is reusable.

//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const defaultURL = "git@github.com:b4ryon/cloak-e2e-scratch.git"

func e2eURL() string {
	if u := os.Getenv("CLOAK_E2E_URL"); u != "" {
		return u
	}
	return defaultURL
}

var binDir string

func TestMain(m *testing.M) {
	if os.Getenv("CLOAK_E2E") != "1" {
		fmt.Fprintln(os.Stderr, "e2e tests skipped (set CLOAK_E2E=1 to run against GitHub)")
		os.Exit(0)
	}
	home, _ := os.UserHomeDir()
	tmp := filepath.Join(home, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp(tmp, "cloak-e2e-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binDir = dir
	bin := filepath.Join(dir, "git-remote-cloak")
	if out, err := exec.Command("go", "build", "-o", bin,
		"github.com/b4ryon/git-remote-cloak/cmd/git-remote-cloak").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n%s", err, out)
		os.Exit(1)
	}
	if err := os.Symlink("git-remote-cloak", filepath.Join(dir, "git-cloak")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// env builds an isolated client environment with a shared key file and the
// e2e branch wired into cloak config.
func env(t *testing.T, home, keyFile, branch string) []string {
	t.Helper()
	cfg := filepath.Join(home, "gitconfig")
	content := "[user]\n\tname = cloak-e2e\n\temail = e2e@cloak.invalid\n" +
		"[init]\n\tdefaultBranch = main\n" +
		"[cloak]\n\tkeyRef = file:" + keyFile + "\n\tbranch = " + branch + "\n"
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{
		"PATH=" + binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_GLOBAL=" + cfg,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_SSH_COMMAND=ssh -o BatchMode=yes",
		"TMPDIR=" + os.TempDir(),
		"CLOAK_LOG=debug",
		"SSH_AUTH_SOCK=" + os.Getenv("SSH_AUTH_SOCK"),
	}
}

func git(t *testing.T, dir string, e []string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = e
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), errb.String(), err
}

func mustGit(t *testing.T, dir string, e []string, args ...string) string {
	t.Helper()
	out, errb, err := git(t, dir, e, args...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, errb)
	}
	return out
}

// uniqueBranch derives a per-run backend branch from the test name and pid
// (no time/random available; pid + name suffices for isolation).
func uniqueBranch(t *testing.T) string {
	safe := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	return fmt.Sprintf("e2e-%s-%d", safe, os.Getpid())
}

// cleanupBranch deletes the backend branch on the host after the test.
func cleanupBranch(t *testing.T, dir string, e []string, branch string) {
	if _, errb, err := git(t, dir, e, "push", e2eURL(), "--delete", "refs/heads/"+branch); err != nil {
		t.Logf("cleanup: could not delete remote branch %s: %s", branch, errb)
	}
}

func keygen(t *testing.T, e []string, keyFile string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(binDir, "git-cloak"), "keygen", "--key", "file:"+keyFile)
	cmd.Env = e
	cmd.Stdin = strings.NewReader("")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
}

func TestLiveRoundTrip(t *testing.T) {
	branch := uniqueBranch(t)
	keyFile := filepath.Join(t.TempDir(), "key")
	homeA := filepath.Join(t.TempDir(), "a")
	if err := os.MkdirAll(homeA, 0o700); err != nil {
		t.Fatal(err)
	}
	envA := env(t, homeA, keyFile, branch)
	keygen(t, envA, keyFile)

	repoA := filepath.Join(t.TempDir(), "repoA")
	mustGit(t, t.TempDir(), envA, "init", repoA)
	if err := os.WriteFile(filepath.Join(repoA, "live.md"), []byte("live e2e content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, repoA, envA, "add", "-A")
	mustGit(t, repoA, envA, "commit", "-m", "c0")
	mustGit(t, repoA, envA, "remote", "add", "origin", "cloak::"+e2eURL())
	defer cleanupBranch(t, repoA, envA, branch)
	mustGit(t, repoA, envA, "push", "-u", "origin", "main")
	head := mustGit(t, repoA, envA, "rev-parse", "HEAD")

	// Clone on a second isolated client with the same key.
	homeB := filepath.Join(t.TempDir(), "b")
	if err := os.MkdirAll(homeB, 0o700); err != nil {
		t.Fatal(err)
	}
	envB := env(t, homeB, keyFile, branch)
	repoB := filepath.Join(t.TempDir(), "repoB")
	if _, errb, err := git(t, t.TempDir(), envB, "clone", "cloak::"+e2eURL(), repoB); err != nil {
		t.Fatalf("clone from GitHub: %v\n%s", err, errb)
	}
	if got := mustGit(t, repoB, envB, "rev-parse", "HEAD"); got != head {
		t.Fatalf("cloned HEAD %s != pushed %s", got, head)
	}
	if b, err := os.ReadFile(filepath.Join(repoB, "live.md")); err != nil || string(b) != "live e2e content\n" {
		t.Fatalf("content mismatch: %q err=%v", b, err)
	}

	// Incremental round trip B -> A.
	if err := os.WriteFile(filepath.Join(repoB, "from-b.md"), []byte("b edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, repoB, envB, "add", "-A")
	mustGit(t, repoB, envB, "commit", "-m", "c1")
	mustGit(t, repoB, envB, "push", "origin", "main")
	mustGit(t, repoA, envA, "pull", "origin", "main")
	if mustGit(t, repoA, envA, "rev-parse", "HEAD") != mustGit(t, repoB, envB, "rev-parse", "HEAD") {
		t.Fatal("A and B did not converge over GitHub")
	}
}

func TestLiveConcurrentForceWithLease(t *testing.T) {
	// Verifies GitHub honors the explicit force-with-lease squash push
	// (the consolidation/repack CAS path) end to end.
	branch := uniqueBranch(t)
	keyFile := filepath.Join(t.TempDir(), "key")
	home := filepath.Join(t.TempDir(), "h")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	e := env(t, home, keyFile, branch)
	keygen(t, e, keyFile)

	repo := filepath.Join(t.TempDir(), "repo")
	mustGit(t, t.TempDir(), e, "init", repo)
	mustGit(t, repo, e, "config", "cloak.geometricFactor", "0") // control repack timing
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(repo, "f.md"), []byte(strings.Repeat("x", (i+1)*100)), 0o644); err != nil {
			t.Fatal(err)
		}
		mustGit(t, repo, e, "add", "-A")
		mustGit(t, repo, e, "commit", "-m", fmt.Sprintf("c%d", i))
	}
	mustGit(t, repo, e, "remote", "add", "origin", "cloak::"+e2eURL())
	defer cleanupBranch(t, repo, e, branch)
	mustGit(t, repo, e, "push", "-u", "origin", "main")

	cmd := exec.Command(filepath.Join(binDir, "git-cloak"), "repack", "--remote", "origin")
	cmd.Dir = repo
	cmd.Env = e
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("repack against GitHub (force-with-lease) failed: %v\n%s", err, out)
	}

	// A fresh clone after the squash must still reconstruct full history.
	home2 := filepath.Join(t.TempDir(), "h2")
	if err := os.MkdirAll(home2, 0o700); err != nil {
		t.Fatal(err)
	}
	e2 := env(t, home2, keyFile, branch)
	repo2 := filepath.Join(t.TempDir(), "repo2")
	if _, errb, err := git(t, t.TempDir(), e2, "clone", "cloak::"+e2eURL(), repo2); err != nil {
		t.Fatalf("clone after repack: %v\n%s", err, errb)
	}
	if mustGit(t, repo2, e2, "rev-list", "--count", "HEAD") != "3" {
		t.Fatal("history not fully recoverable after repack on GitHub")
	}
}
