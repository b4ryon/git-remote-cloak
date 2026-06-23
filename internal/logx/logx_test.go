// Unit tests for the logging fanout: level routing between stderr and file
// handlers, the cloak: stderr format, level parsing, and rotation.
package logx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFanoutLevelRouting(t *testing.T) {
	var errOut bytes.Buffer
	logPath := filepath.Join(t.TempDir(), "log")
	lg, closer := Setup(Options{
		Stderr: &errOut, StderrLevel: slog.LevelWarn,
		FilePath: logPath, FileLevel: slog.LevelDebug, Role: "helper",
	})
	lg.Debug("debug detail", "k", 1)
	lg.Info("info detail")
	lg.Warn("user facing problem", "path", "/x")
	closer()

	if s := errOut.String(); strings.Contains(s, "debug detail") || strings.Contains(s, "info detail") {
		t.Fatalf("stderr received sub-warn records: %q", s)
	}
	if s := errOut.String(); !strings.Contains(s, "cloak: user facing problem") || !strings.Contains(s, "path=/x") {
		t.Fatalf("stderr format wrong: %q", s)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"debug detail", "info detail", "user facing problem"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("file log missing %q:\n%s", want, b)
		}
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(string(b), "\n", 2)[0]), &rec); err != nil {
		t.Fatalf("file log is not JSON lines: %v", err)
	}
	if rec["sid"] == "" || rec["role"] != "helper" {
		t.Fatalf("session attrs missing: %v", rec)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"error": slog.LevelError, "warn": slog.LevelWarn, "warning": slog.LevelWarn,
		"info": slog.LevelInfo, "debug": slog.LevelDebug,
		"": slog.LevelInfo, "bogus": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in, slog.LevelInfo); got != want {
			t.Fatalf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFileLevelEnvWins(t *testing.T) {
	t.Setenv("CLOAK_LOG", "debug")
	if got := FileLevel("error"); got != slog.LevelDebug {
		t.Fatalf("env did not win: %v", got)
	}
	t.Setenv("CLOAK_LOG", "")
	if got := FileLevel("error"); got != slog.LevelError {
		t.Fatalf("config not used: %v", got)
	}
}

func TestRotation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(logPath, make([]byte, maxLogSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, closer := Setup(Options{Stderr: &bytes.Buffer{}, StderrLevel: slog.LevelWarn,
		FilePath: logPath, FileLevel: slog.LevelInfo})
	closer()
	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Fatalf("rotation did not produce log.1: %v", err)
	}
	if fi, err := os.Stat(logPath); err != nil || fi.Size() > 1024 {
		t.Fatalf("fresh log not started: %v size=%d", err, fi.Size())
	}
}

func TestFileOpenFailureIsSilent(t *testing.T) {
	var errOut bytes.Buffer
	lg, closer := Setup(Options{Stderr: &errOut, StderrLevel: slog.LevelWarn,
		FilePath: filepath.Join(t.TempDir(), "missing-dir", "log"), FileLevel: slog.LevelInfo})
	lg.Warn("still works")
	closer()
	if !strings.Contains(errOut.String(), "still works") {
		t.Fatal("logger broken when file cannot open")
	}
}
