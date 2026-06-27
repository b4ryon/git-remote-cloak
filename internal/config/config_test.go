// Unit tests for cloak.* config resolution against a real throwaway repo.
package config

import (
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/logx"
)

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", dir).CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	return filepath.Join(dir, ".git")
}

func TestDefaultsWhenUnset(t *testing.T) {
	lg, _ := logx.Setup(logx.Options{Stderr: testWriter{t}, StderrLevel: slog.LevelError})
	g := gitx.New(lg)
	c, err := Load(g, initRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	d := Defaults()
	if c != d {
		t.Fatalf("got %+v, want defaults %+v", c, d)
	}
}

func TestLoadOverrides(t *testing.T) {
	gitDir := initRepo(t)
	for k, v := range map[string]string{
		"cloak.keyRef":          "file:/x/key",
		"cloak.geometricFactor": "3",
		"cloak.pushRetries":     "9",
		"cloak.branch":          "vault",
		"cloak.logLevel":        "debug",
		"cloak.maxPackBytes":    "2097152",
	} {
		if out, err := exec.Command("git", "--git-dir", gitDir, "config", k, v).CombinedOutput(); err != nil {
			t.Fatalf("config %s: %v\n%s", k, err, out)
		}
	}
	lg, _ := logx.Setup(logx.Options{Stderr: testWriter{t}, StderrLevel: slog.LevelError})
	c, err := Load(gitx.New(lg), gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyRef != "file:/x/key" || c.GeometricFactor != 3 || c.PushRetries != 9 ||
		c.Branch != "vault" || c.LogLevel != "debug" || c.MaxPackBytes != 2097152 {
		t.Fatalf("overrides not applied: %+v", c)
	}
}

func TestBadValuesKeepDefaults(t *testing.T) {
	gitDir := initRepo(t)
	for k, v := range map[string]string{
		"cloak.geometricFactor": "-1",
		"cloak.pushRetries":     "zero",
		"cloak.maxPackBytes":    "-5", // below min 0
	} {
		if out, err := exec.Command("git", "--git-dir", gitDir, "config", k, v).CombinedOutput(); err != nil {
			t.Fatalf("config %s: %v\n%s", k, err, out)
		}
	}
	lg, _ := logx.Setup(logx.Options{Stderr: testWriter{t}, StderrLevel: slog.LevelError})
	c, err := Load(gitx.New(lg), gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if c.GeometricFactor != Defaults().GeometricFactor || c.PushRetries != Defaults().PushRetries ||
		c.MaxPackBytes != Defaults().MaxPackBytes {
		t.Fatalf("bad values overrode defaults: %+v", c)
	}
}

// TestIsNoMatchingKeys pins the sentinel detection Load uses to tell git
// config's "no cloak.* key set" (exit 1, return defaults) apart from a real
// failure (surface it). The wrapped-error case is the regression guard: the
// prior direct type assertion (err.(*gitx.GitError)) returned false for a
// wrapped GitError, which would have turned a benign "no keys" result into a
// surfaced error; errors.As sees through the wrap.
func TestIsNoMatchingKeys(t *testing.T) {
	exit1 := &gitx.GitError{Args: []string{"config"}, ExitCode: 1}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"bare exit 1", exit1, true},
		{"wrapped exit 1", fmt.Errorf("read cloak config: %w", exit1), true},
		{"exit 2 is a real failure", &gitx.GitError{Args: []string{"config"}, ExitCode: 2}, false},
		{"non-git error", fmt.Errorf("some other error"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := isNoMatchingKeys(c.err); got != c.want {
			t.Errorf("%s: isNoMatchingKeys = %v, want %v", c.name, got, c.want)
		}
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
