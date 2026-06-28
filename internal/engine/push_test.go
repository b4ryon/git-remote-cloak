// Unit tests for push-path pieces that need no remote host: the pack
// header sniffer (empty-pack detection), pushPlan cleanup, and the
// manifest-head selection against a local repository.
package engine

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

func TestPackHeadSnifferCount(t *testing.T) {
	// "PACK", version 2, count 42, then payload bytes.
	hdr := []byte{'P', 'A', 'C', 'K', 0, 0, 0, 2, 0, 0, 0, 42, 0xde, 0xad}
	s := &packHeadSniffer{dst: io.Discard}
	// Split across writes to exercise partial header accumulation.
	if _, err := s.Write(hdr[:5]); err != nil {
		t.Fatal(err)
	}
	if got := s.count(); got != 0 {
		t.Fatalf("count before full header = %d, want 0", got)
	}
	if _, err := s.Write(hdr[5:]); err != nil {
		t.Fatal(err)
	}
	if got := s.count(); got != 42 {
		t.Fatalf("count = %d, want 42", got)
	}
}

func TestPushPlanAbort(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "pack1.age")
	f2 := filepath.Join(dir, "pack2.age")
	for _, f := range []string{f1, f2} {
		if err := os.WriteFile(f, []byte("ct"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A bin-packed push carries several temp packs; abort must remove all of them.
	plan := &pushPlan{packs: []plannedPack{{path: f1}, {path: f2}}}
	plan.abort()
	for _, f := range []string{f1, f2} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("abort left temp pack in place: %v", err)
		}
	}

	var nilPlan *pushPlan
	nilPlan.abort() // must not panic
	(&pushPlan{}).abort()
}

func TestHeadForManifest(t *testing.T) {
	g := gitx.New(slog.New(slog.DiscardHandler))
	dir := t.TempDir()
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--initial-branch", "main", dir); err != nil {
		t.Fatal(err)
	}
	e := &Engine{G: g, LocalGitDir: filepath.Join(dir, ".git")}

	withMain := map[string]string{"refs/heads/main": oid}
	if got := e.headForManifest(nil, withMain); got != "refs/heads/main" {
		t.Fatalf("local HEAD branch in refs: got %q, want refs/heads/main", got)
	}

	prev := m("refs/heads/dev", "refs/heads/dev")
	noMain := map[string]string{"refs/heads/dev": oid}
	if got := e.headForManifest(prev, noMain); got != "refs/heads/dev" {
		t.Fatalf("previous head fallback: got %q, want refs/heads/dev", got)
	}

	if got := e.headForManifest(prev, map[string]string{"refs/tags/v1": oid}); got != "" {
		t.Fatalf("no valid head: got %q, want empty", got)
	}
}
