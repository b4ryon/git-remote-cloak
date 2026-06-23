// Unit tests for per-remote state: directory naming, pin persistence, and
// the rollback/tamper decisions of CheckPin.
package state

import (
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
