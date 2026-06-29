// Unit tests for per-remote state: directory naming, pin persistence, and
// the rollback/tamper decisions of CheckPin.
package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

func TestDirName(t *testing.T) {
	if got := DirName("origin", "git@github.com:a/b.git"); got != "origin" {
		t.Fatalf("named remote -> %q", got)
	}
	hashed := DirName("", "git@github.com:a/b.git")
	if !strings.HasPrefix(hashed, "url-") {
		t.Fatalf("url fallback -> %q", hashed)
	}
	if got := DirName("cloak::git@x:y", "cloak::git@x:y"); got != hashed[:0]+got || !strings.HasPrefix(got, "url-") {
		t.Fatalf("url-as-name -> %q, want url- prefix", got)
	}
	if DirName("", "urlA") == DirName("", "urlB") {
		t.Fatal("different urls hash to same dir")
	}
}

func openDir(t *testing.T) *Dir {
	t.Helper()
	d, err := Open(t.TempDir(), "origin", "u")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPinRoundTrip(t *testing.T) {
	d := openDir(t)
	if _, ok, err := d.LoadPin(); err != nil || ok {
		t.Fatalf("fresh dir pin: ok=%v err=%v", ok, err)
	}
	want := Pin{Generation: 42, ManifestHash: strings.Repeat("ab", 32)}
	if err := d.SavePin(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := d.LoadPin()
	if err != nil || !ok || got != want {
		t.Fatalf("pin round trip: got=%+v ok=%v err=%v", got, ok, err)
	}
}

func TestLoadPinRejectsMalformedHash(t *testing.T) {
	for _, bad := range []string{
		"7 " + strings.Repeat("a", 63), // 63 hex (too short)
		"7 " + strings.Repeat("a", 65), // 65 hex (too long)
		"7 " + strings.Repeat("A", 64), // uppercase
		"7 " + strings.Repeat("g", 64), // non-hex digit
		"7 deadbeef",                   // short token
	} {
		d := openDir(t)
		if err := os.WriteFile(filepath.Join(d.Root, pinFile), []byte(bad+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := d.LoadPin(); ok || err == nil {
			t.Fatalf("LoadPin accepted malformed pin %q: ok=%v err=%v", bad, ok, err)
		}
	}
	// Control: a valid 64-hex pin still loads.
	d := openDir(t)
	want := Pin{Generation: 5, ManifestHash: strings.Repeat("ab", 32)}
	if err := d.SavePin(want); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := d.LoadPin(); err != nil || !ok || got != want {
		t.Fatalf("valid pin failed to load: got=%+v ok=%v err=%v", got, ok, err)
	}
}

func TestCheckPinDecisions(t *testing.T) {
	d := openDir(t)
	hashA, hashB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	m := func(gen uint64) *manifest.Manifest {
		mm := manifest.New()
		mm.Generation = gen
		return mm
	}
	// TOFU: anything accepted before a pin exists.
	if err := d.CheckPin(m(7), hashA); err != nil {
		t.Fatalf("TOFU: %v", err)
	}
	if err := d.SavePin(Pin{Generation: 7, ManifestHash: hashA}); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckPin(m(8), hashB); err != nil {
		t.Fatalf("higher generation refused: %v", err)
	}
	if err := d.CheckPin(m(7), hashA); err != nil {
		t.Fatalf("equal generation, same hash refused: %v", err)
	}
	if err := d.CheckPin(m(7), hashB); err == nil {
		t.Fatal("equal generation with different hash accepted")
	} else if k, _ := cloakerr.KindOf(err); k != cloakerr.Tamper {
		t.Fatalf("equal-gen mismatch not Tamper: %v", err)
	}
	if err := d.CheckPin(m(6), hashB); err == nil {
		t.Fatal("generation regression accepted")
	} else if k, _ := cloakerr.KindOf(err); k != cloakerr.Rollback {
		t.Fatalf("regression not Rollback: %v", err)
	}
	if err := d.CheckPin(nil, ""); err == nil {
		t.Fatal("empty remote with existing pin accepted")
	} else if k, _ := cloakerr.KindOf(err); k != cloakerr.Rollback {
		t.Fatalf("empty-remote regression not Rollback: %v", err)
	}
}

func TestAppliedSet(t *testing.T) {
	d := openDir(t)
	set, err := d.AppliedSet()
	if err != nil || len(set) != 0 {
		t.Fatalf("fresh applied set: %v %v", set, err)
	}
	if err := d.MarkApplied("p1", "p2"); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkApplied("p3"); err != nil {
		t.Fatal(err)
	}
	set, err = d.AppliedSet()
	if err != nil || !set["p1"] || !set["p2"] || !set["p3"] || len(set) != 3 {
		t.Fatalf("applied set after marks: %v %v", set, err)
	}
}

// TestMarkAppliedRecoversTornFinalLine exercises MarkApplied's crash-recovery
// guard against the on-disk residue of an interrupted write. Before MarkApplied
// became an atomic temp-file-then-rename, it used O_APPEND, so a crash partway
// through an append could leave the "applied" file ending without its trailing
// newline (the id bytes landed but the '\n' did not). Such a legacy/torn file
// may still exist on disk. MarkApplied must re-establish the line boundary
// before appending so the new id is recorded as its own line rather than
// concatenated onto the unterminated tail -- which would fabricate one mangled
// id and lose two real ones, exactly the inconsistent state the atomicity work
// is meant to preclude.
func TestMarkAppliedRecoversTornFinalLine(t *testing.T) {
	d := openDir(t)
	// A legacy append that crashed after writing idB's bytes but before its
	// newline: idA is cleanly terminated, idB is complete but unterminated.
	idA, idB, idC := "aaaa", "bbbb", "cccc"
	torn := idA + "\n" + idB // no trailing newline on idB
	if err := os.WriteFile(filepath.Join(d.Root, appliedFile), []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkApplied(idC); err != nil {
		t.Fatal(err)
	}
	set, err := d.AppliedSet()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{idA: true, idB: true, idC: true}
	if len(set) != len(want) {
		t.Fatalf("torn-line recovery: got %v, want %v", set, want)
	}
	for id := range want {
		if !set[id] {
			t.Fatalf("torn-line recovery dropped %q: got %v", id, set)
		}
	}
	// The specific failure the guard prevents: the unterminated tail and the new
	// id must never coalesce into one fabricated id.
	if set[idB+idC] {
		t.Fatalf("torn-line recovery concatenated %q onto the unterminated tail: got %v", idC, set)
	}
	// The rewrite must leave a well-formed, newline-terminated file so the next
	// writer sees an intact line boundary and need not re-run the guard.
	b, err := os.ReadFile(filepath.Join(d.Root, appliedFile))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(b); n == 0 || b[n-1] != '\n' {
		t.Fatalf("recovered applied file is not newline-terminated: %q", b)
	}
}

// TestWriteStateFileFailureLeavesPriorStateIntact verifies the core atomicity
// guarantee of writeStateFile (and therefore of SavePin/SaveRepoID/MarkApplied,
// which all route through it): an interrupted write that fails before its rename
// can commit must leave the previously committed state file fully intact, never
// truncated, emptied, or partially overwritten. This is precisely what makes the
// temp-file-then-rename design crash-safe -- the live pin file is only ever
// replaced by an atomic rename of an already-fully-written temp file, so a write
// that dies partway through cannot corrupt the prior pin. The earlier ioerr
// "write" subtest only asserts that such a failure is reported with context; it
// never checks that the prior on-disk state survives, which is the property an
// interrupted push actually depends on.
//
// The interruption is modeled by planting a directory at the fixed temp path
// SavePin uses ("pin" under TmpDir), so writeFileSync's O_WRONLY open returns
// EISDIR and the write aborts before touching the live pin file. This also pins
// the design itself: were writeStateFile ever refactored to write the live file
// in place, the planted temp directory would be irrelevant, the second SavePin
// would succeed, and the "expected failure" assertion below would catch it.
func TestWriteStateFileFailureLeavesPriorStateIntact(t *testing.T) {
	d := openDir(t)
	want := Pin{Generation: 9, ManifestHash: strings.Repeat("ab", 32)}
	if err := d.SavePin(want); err != nil {
		t.Fatal(err)
	}
	// After the first SavePin, its temp file has been renamed away, so the temp
	// path is free to plant a directory at -- forcing the next write to fail at
	// its open, before any rename into the state directory.
	if err := os.Mkdir(filepath.Join(d.TmpDir(), "pin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.SavePin(Pin{Generation: 10, ManifestHash: strings.Repeat("cd", 32)}); err == nil {
		t.Fatal("expected the interrupted write to fail (temp path is a directory), got nil")
	}
	got, ok, err := d.LoadPin()
	if err != nil || !ok {
		t.Fatalf("prior pin became unreadable after a failed write: ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Fatalf("a failed write damaged the prior pin: got %+v, want %+v", got, want)
	}
}

func TestUrlHashDirAdoptedByNamedRemote(t *testing.T) {
	common := t.TempDir()
	d1, err := Open(common, "cloak::u", "cloak::u")
	if err != nil {
		t.Fatal(err)
	}
	if err := d1.SavePin(Pin{Generation: 3, ManifestHash: strings.Repeat("cc", 32)}); err != nil {
		t.Fatal(err)
	}
	d2, err := Open(common, "origin", "cloak::u")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d2.LoadPin(); !ok {
		t.Fatal("named remote did not adopt the url-hash state dir (TOFU pin lost)")
	}
}
