// Tests for the pre-flight pack-size guard: the pure show-list/cat-file parsers,
// the consolidation-overflow prediction, the largest-files report against a real
// repo, and checkPackLimit's threshold + TooLarge classification.
package engine

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/config"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

const (
	oidA = "1111111111111111111111111111111111111111"
	oidB = "2222222222222222222222222222222222222222"
	oidC = "3333333333333333333333333333333333333333"
)

func TestParseObjectPaths(t *testing.T) {
	in := "4444444444444444444444444444444444444444\n" + // commit: no path, dropped
		oidA + " big.bin\n" +
		oidB + " dir name/with spaces.txt\n" + // path with spaces preserved
		"notanoid foo\n" + // malformed oid, dropped
		"\n"
	got := parseObjectPaths(in)
	if len(got) != 2 {
		t.Fatalf("got %d paths, want 2: %v", len(got), got)
	}
	if got[oidA] != "big.bin" || got[oidB] != "dir name/with spaces.txt" {
		t.Fatalf("paths mismatch: %v", got)
	}
}

func TestCombineBlobInfo(t *testing.T) {
	paths := map[string]string{oidA: "a.bin", oidB: "b.txt"}
	catOut := oidA + " blob 100\n" +
		oidB + " blob 50\n" +
		oidC + " blob 999\n" + // no path -> skipped
		oidA + " tree 10\n" + // non-blob -> skipped (also same oid, but type filters it)
		"garbage line\n"
	infos := combineBlobInfo(paths, catOut)
	if len(infos) != 2 {
		t.Fatalf("got %d infos, want 2: %v", len(infos), infos)
	}
	bySize := map[string]int64{}
	for _, o := range infos {
		bySize[o.path] = o.size
	}
	if bySize["a.bin"] != 100 || bySize["b.txt"] != 50 {
		t.Fatalf("sizes mismatch: %v", bySize)
	}
}

func TestConsolidationWouldExceed(t *testing.T) {
	victims := []manifest.Pack{{Size: 60}, {Size: 60}} // sum 120
	cases := []struct {
		max  int64
		want bool
	}{
		{0, false},   // disabled
		{100, true},  // 120 > 100
		{120, false}, // 120 == 120, not over
		{200, false}, // under
	}
	for _, c := range cases {
		e := &Engine{Cfg: config.Config{MaxPackBytes: c.max}}
		if got := e.consolidationWouldExceed(victims); got != c.want {
			t.Errorf("max=%d: consolidationWouldExceed = %v, want %v", c.max, got, c.want)
		}
	}
}

// realRepoWithBlobs builds a temp repo with a large and a small file and returns
// its git dir and HEAD oid.
func realRepoWithBlobs(t *testing.T) (gitDir, head string) {
	t.Helper()
	repo := t.TempDir()
	gitInDir(t, repo, "init", "-q")
	if err := os.WriteFile(filepath.Join(repo, "big.bin"), []byte(strings.Repeat("x", 5000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "small.txt"), []byte("tiny"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitInDir(t, repo, "add", "-A")
	gitInDir(t, repo, "commit", "-q", "-m", "c1")
	gitDir = filepath.Join(repo, ".git")
	head = gitInDir(t, repo, "rev-parse", "HEAD")
	return gitDir, head
}

func newCfgEngine(gitDir string, max int64) *Engine {
	e := newEngine(gitDir)
	e.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	e.Cfg = config.Config{MaxPackBytes: max}
	return e
}

func TestLargestObjects(t *testing.T) {
	gitDir, head := realRepoWithBlobs(t)
	infos := newCfgEngine(gitDir, 0).largestObjects([]string{head}, nil)
	if len(infos) == 0 {
		t.Fatal("largestObjects returned nothing")
	}
	if infos[0].path != "big.bin" {
		t.Fatalf("largest file = %q (size %d), want big.bin; all=%v", infos[0].path, infos[0].size, infos)
	}
	if infos[0].size != 5000 {
		t.Fatalf("big.bin size = %d, want 5000", infos[0].size)
	}
}

func TestCheckPackLimit(t *testing.T) {
	gitDir, head := realRepoWithBlobs(t)

	// Disabled (0) and under-limit both accept.
	if err := newCfgEngine(gitDir, 0).checkPackLimit("push", 1<<30, []string{head}, nil); err != nil {
		t.Fatalf("disabled limit should accept: %v", err)
	}
	if err := newCfgEngine(gitDir, 1000).checkPackLimit("push", 500, []string{head}, nil); err != nil {
		t.Fatalf("under limit should accept: %v", err)
	}

	// Over limit: classified TooLarge, names the offending file, flags it as
	// alone exceeding the limit.
	err := newCfgEngine(gitDir, 100).checkPackLimit("push", 5000, []string{head}, nil)
	if err == nil {
		t.Fatal("over limit should be refused")
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.TooLarge {
		t.Fatalf("over-limit error not TooLarge: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "exceeds") || !strings.Contains(msg, "big.bin") {
		t.Fatalf("error lacks size/file detail: %q", msg)
	}
	if !strings.Contains(msg, "alone exceeds the limit") {
		t.Fatalf("single-file-over-limit not flagged: %q", msg)
	}
}

// TestMaybeConsolidateSkipsOverLimit proves an over-limit consolidation is
// skipped (returning squash=false) without mutating the plan, so the push
// proceeds with the un-consolidated pack set. It needs no backend because the
// skip returns before consolidate() runs.
func TestMaybeConsolidateSkipsOverLimit(t *testing.T) {
	e := &Engine{
		Cfg: config.Config{GeometricFactor: 2, MaxPackBytes: 30},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	// Four equal packs violate the geometric invariant (factor 2) and sum to 40,
	// over the 30-byte limit, so consolidation must be skipped.
	packs := []manifest.Pack{{ID: oidA, Size: 10}, {ID: oidB, Size: 10}, {ID: oidC, Size: 10},
		{ID: "4444444444444444444444444444444444444444", Size: 10}}
	plan := &pushPlan{man: &manifest.Manifest{Packs: packs}}
	cur := &RemoteState{Head: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

	squash, err := e.maybeConsolidate(cur, plan)
	if err != nil {
		t.Fatalf("skip path should not error: %v", err)
	}
	if squash {
		t.Fatal("over-limit consolidation should be skipped (squash=false)")
	}
	if len(plan.man.Packs) != 4 || plan.packID != "" {
		t.Fatalf("plan was mutated by a skipped consolidation: packs=%d packID=%q", len(plan.man.Packs), plan.packID)
	}
}

// FuzzParseObjectPaths pins the rev-list parser: every key is a 40-hex oid,
// every value is non-empty, and the parse is deterministic.
func FuzzParseObjectPaths(f *testing.F) {
	f.Add(oidA + " path/to/file\n4444444444444444444444444444444444444444\n")
	f.Add("garbage\n\n" + oidB + " a b c")
	f.Add(oidC + "  leading-space-path")
	f.Fuzz(func(t *testing.T, in string) {
		got := parseObjectPaths(in)
		for oid, path := range got {
			if !manifest.IsLowerHex(oid, 40) {
				t.Fatalf("non-oid key %q", oid)
			}
			if path == "" {
				t.Fatalf("empty path for %q", oid)
			}
		}
		again := parseObjectPaths(in)
		if len(again) != len(got) {
			t.Fatalf("not deterministic: %d then %d", len(got), len(again))
		}
	})
}
