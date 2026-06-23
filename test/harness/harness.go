// Package harness provides shared plumbing for the integration and security
// test suites: it compiles the helper binary once per test run, enforces the
// operator's ~/tmp temp-file convention, and (from M2 on) provides Host and
// Client fixtures that run real git against hermetic local bare repositories.
package harness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var (
	once     sync.Once
	binDir   string
	buildErr error
)

// EnsureBuilt compiles git-remote-cloak once into a temp directory (under
// TMPDIR) with a git-cloak symlink beside it, returning that directory. The
// directory is intended for PATH injection in front of test clients.
func EnsureBuilt() (string, error) {
	once.Do(func() {
		dir, err := os.MkdirTemp("", "cloak-bin-")
		if err != nil {
			buildErr = err
			return
		}
		bin := filepath.Join(dir, "git-remote-cloak")
		cmd := exec.Command("go", "build", "-o", bin,
			"github.com/b4ryon/git-remote-cloak/cmd/git-remote-cloak")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("building helper: %v\n%s", err, out)
			return
		}
		if err := os.Symlink("git-remote-cloak", filepath.Join(dir, "git-cloak")); err != nil {
			buildErr = err
			return
		}
		binDir = dir
	})
	return binDir, buildErr
}

// RequireTmpHome fails unless the effective temp directory is under
// $HOME/tmp, enforcing the operator's temp-file convention (the Makefile
// exports TMPDIR; a bare `go test` run without it is rejected here).
func RequireTmpHome() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	want := filepath.Join(home, "tmp")
	got := os.TempDir()
	if got != want && !strings.HasPrefix(got, want+string(os.PathSeparator)) {
		return fmt.Errorf("temp dir is %s; these tests must run with TMPDIR under %s (use the make targets)", got, want)
	}
	return nil
}
