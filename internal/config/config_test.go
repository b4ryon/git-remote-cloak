// Unit tests for cloak.* config resolution against a real throwaway repo.
package config

import (
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
		c.Branch != "vault" || c.LogLevel != "debug" {
		t.Fatalf("overrides not applied: %+v", c)
	}
}

func TestBadValuesKeepDefaults(t *testing.T) {
	gitDir := initRepo(t)
	for k, v := range map[string]string{
		"cloak.geometricFactor": "-1",
		"cloak.pushRetries":     "zero",
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
	if c.GeometricFactor != Defaults().GeometricFactor || c.PushRetries != Defaults().PushRetries {
		t.Fatalf("bad values overrode defaults: %+v", c)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
