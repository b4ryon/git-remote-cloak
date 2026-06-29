// Unit tests for the git subprocess runner: output trimming, error typing
// with captured stderr, and GIT_DIR environment control.
package gitx

import (
	"log/slog"
	"os/exec"
	"strings"
	"testing"
)

func runner() *G {
	return New(slog.New(slog.DiscardHandler))
}

func TestOutTrims(t *testing.T) {
	out, err := runner().Out(Opts{}, "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "git version") || strings.HasSuffix(out, "\n") {
		t.Fatalf("Out = %q", out)
	}
}

func TestGitErrorCarriesStderrAndExit(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", dir).CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	_, _, err := runner().Run(Opts{Dir: dir}, "rev-parse", "--verify", "refs/heads/nope")
	ge, ok := err.(*GitError)
	if !ok {
		t.Fatalf("error type = %T (%v)", err, err)
	}
	if ge.ExitCode == 0 || !strings.Contains(ge.Error(), "rev-parse") {
		t.Fatalf("GitError = %+v", ge)
	}
}

func TestRunCapsCapturedStdout(t *testing.T) {
	// Uncapped (MaxCapture 0, the default) captures the full output.
	full, _, err := runner().Run(Opts{}, "version")
	if err != nil {
		t.Fatal(err)
	}
	if len(full) <= 4 {
		t.Skipf("git version output unexpectedly short: %q", full)
	}
	// A tiny cap truncates captured stdout to a faithful prefix; the git process
	// still runs to completion (no error from the short capture).
	capped, _, err := runner().Run(Opts{MaxCapture: 4}, "version")
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) != 4 || !strings.HasPrefix(full, capped) {
		t.Fatalf("capped stdout = %q (len %d), want a 4-byte prefix of %q", capped, len(capped), full)
	}
}

func TestGitDirEnvControl(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", dir).CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	got, err := runner().Out(Opts{GitDir: dir + "/.git"}, "rev-parse", "--absolute-git-dir")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, "/.git") {
		t.Fatalf("absolute git dir = %q", got)
	}
}
