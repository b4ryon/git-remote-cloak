// Unit tests for the backend mirror against a local bare "host" repository
// (no network): empty-remote detection, fast-forward push and fetch round
// trip, blob reads, pack blob oid listing, and the compare-and-swap
// outcomes of PushFF and PushLease.
package backend

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

// newHost creates a local bare repository configured like the integration
// harness host (filter support enabled, backend branch "cloak").
func newHost(t *testing.T) (g *gitx.G, hostDir string) {
	t.Helper()
	g = gitx.New(slog.New(slog.DiscardHandler))
	hostDir = filepath.Join(t.TempDir(), "host.git")
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--bare", "--initial-branch", "cloak", hostDir); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: hostDir}, "config", "uploadpack.allowfilter", "true"); err != nil {
		t.Fatal(err)
	}
	return g, hostDir
}

func openMirror(t *testing.T, g *gitx.G, host string) *Backend {
	t.Helper()
	b, err := Open(g, filepath.Join(t.TempDir(), "backend.git"), host, "cloak", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seedCommit builds a root backend commit in b's mirror with one manifest
// blob and one pack blob, returning the commit and the pack blob oid.
func seedCommit(t *testing.T, b *Backend, manifestCT, packCT string, generation uint64) (commit, packOID string) {
	t.Helper()
	moid, err := b.HashObject(strings.NewReader(manifestCT))
	if err != nil {
		t.Fatal(err)
	}
	packOID, err = b.HashObject(strings.NewReader(packCT))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 32)
	commit, err = b.BuildCommit("", moid, map[string]string{id: packOID}, generation)
	if err != nil {
		t.Fatal(err)
	}
	return commit, packOID
}

func TestFetchEmptyRemote(t *testing.T) {
	g, host := newHost(t)
	b := openMirror(t, g, host)
	head, empty, err := b.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if !empty || head != "" {
		t.Fatalf("Fetch on empty host = (%q, empty=%v), want (\"\", true)", head, empty)
	}
}

func TestPushFFFetchReadRoundTrip(t *testing.T) {
	g, host := newHost(t)
	a := openMirror(t, g, host)
	commit, packOID := seedCommit(t, a, "manifest-ct", "pack-ct", 1)
	res, err := a.PushFF(commit)
	if err != nil || res != PushOK {
		t.Fatalf("PushFF = (%v, %v), want PushOK", res, err)
	}

	b := openMirror(t, g, host)
	head, empty, err := b.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if empty || head != commit {
		t.Fatalf("Fetch = (%q, empty=%v), want (%q, false)", head, empty, commit)
	}
	ct, err := b.ReadBlobBytes(head, "manifest.age")
	if err != nil {
		t.Fatal(err)
	}
	if string(ct) != "manifest-ct" {
		t.Fatalf("manifest blob = %q, want %q", ct, "manifest-ct")
	}
	oids, err := b.PackBlobOIDs(head)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 32)
	if len(oids) != 1 || oids[id] != packOID {
		t.Fatalf("PackBlobOIDs = %v, want {%s: %s}", oids, id, packOID)
	}
}

func TestPackBlobOIDsEmptyCommit(t *testing.T) {
	g, host := newHost(t)
	b := openMirror(t, g, host)
	oids, err := b.PackBlobOIDs("")
	if err != nil || len(oids) != 0 {
		t.Fatalf("PackBlobOIDs(\"\") = (%v, %v), want empty map", oids, err)
	}
}

func TestPushFFLosesCAS(t *testing.T) {
	g, host := newHost(t)
	a := openMirror(t, g, host)
	c1, _ := seedCommit(t, a, "m1", "p1", 1)
	if res, err := a.PushFF(c1); err != nil || res != PushOK {
		t.Fatalf("initial push = (%v, %v)", res, err)
	}

	// A second writer that never fetched pushes an unrelated root commit:
	// the push must classify as a lost compare-and-swap, not an error.
	b := openMirror(t, g, host)
	c2, _ := seedCommit(t, b, "m2", "p2", 2)
	res, err := b.PushFF(c2)
	if err != nil {
		t.Fatalf("PushFF returned error: %v", err)
	}
	if res != PushCASLost {
		t.Fatalf("PushFF = %v, want PushCASLost", res)
	}
}

func TestPushLeaseOKAndStale(t *testing.T) {
	g, host := newHost(t)
	a := openMirror(t, g, host)
	c1, _ := seedCommit(t, a, "m1", "p1", 1)
	if res, err := a.PushFF(c1); err != nil || res != PushOK {
		t.Fatalf("initial push = (%v, %v)", res, err)
	}

	c2, _ := seedCommit(t, a, "m2", "p2", 2)
	res, err := a.PushLease(c2, c1)
	if err != nil || res != PushOK {
		t.Fatalf("PushLease with matching lease = (%v, %v), want PushOK", res, err)
	}

	// Remote is now at c2; a lease still expecting c1 must lose the CAS.
	c3, _ := seedCommit(t, a, "m3", "p3", 3)
	res, err = a.PushLease(c3, c1)
	if err != nil {
		t.Fatalf("stale PushLease returned error: %v", err)
	}
	if res != PushCASLost {
		t.Fatalf("stale PushLease = %v, want PushCASLost", res)
	}
}
