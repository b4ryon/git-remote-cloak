// Regression tests for the pin-reliability hardening:
//   - SavePins persists both pins together with byte-identical on-disk format to
//     the individual SavePin/SaveRepoID writers (no format change).
//   - state.Open surfaces a failed url-hash -> named state-dir adoption instead
//     of silently abandoning the old dir's pin (reverting to TOFU).
package state

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSavePinsFormatMatchesIndividualWrites proves the combined writer produces
// the exact same on-disk bytes as the pre-existing SavePin + SaveRepoID pair, so
// the fix changes durability ordering only, never the on-disk format, and the
// records still round-trip through LoadPin/LoadRepoID.
func TestSavePinsFormatMatchesIndividualWrites(t *testing.T) {
	p := Pin{Generation: 7, ManifestHash: strings.Repeat("ab", 32)}
	const id = "repo-identity-xyz"

	combined := openDir(t)
	if err := combined.SavePins(p, id); err != nil {
		t.Fatalf("SavePins: %v", err)
	}
	individual := openDir(t)
	if err := individual.SavePin(p); err != nil {
		t.Fatalf("SavePin: %v", err)
	}
	if err := individual.SaveRepoID(id); err != nil {
		t.Fatalf("SaveRepoID: %v", err)
	}

	for _, f := range []string{pinFile, repoIDFile} {
		a, err := os.ReadFile(filepath.Join(combined.Root, f))
		if err != nil {
			t.Fatalf("read combined %s: %v", f, err)
		}
		b, err := os.ReadFile(filepath.Join(individual.Root, f))
		if err != nil {
			t.Fatalf("read individual %s: %v", f, err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("%s on-disk format differs: SavePins=%q individual=%q", f, a, b)
		}
	}

	gotPin, ok, err := combined.LoadPin()
	if err != nil || !ok || gotPin != p {
		t.Fatalf("LoadPin after SavePins = %+v ok=%v err=%v, want %+v", gotPin, ok, err, p)
	}
	gotID, ok, err := combined.LoadRepoID()
	if err != nil || !ok || gotID != id {
		t.Fatalf("LoadRepoID after SavePins = %q ok=%v err=%v, want %q", gotID, ok, err, id)
	}
}

// TestOpenSurfacesAdoptionRenameFailure proves a failed url-hash -> named
// state-dir adoption is reported, not silently swallowed (which would abandon
// the old dir's TOFU pin and downgrade the remote to trust-on-first-use). A
// read-only cloak/ base makes the adoption rename fail deterministically.
func TestOpenSurfacesAdoptionRenameFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions, so the rename cannot be made to fail")
	}
	gitDir := t.TempDir()
	base := filepath.Join(gitDir, "cloak")
	const url = "git@example.com:owner/repo.git"
	hashed := filepath.Join(base, DirName("", url))
	if err := os.MkdirAll(hashed, 0o700); err != nil {
		t.Fatal(err)
	}
	// A pin in the old dir that must not be silently abandoned.
	if err := os.WriteFile(filepath.Join(hashed, pinFile), []byte("3 deadbeef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o500); err != nil { // read+exec, no write: rename into base fails
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) }) // let t.TempDir cleanup remove it

	if _, err := Open(gitDir, "origin", url); err == nil {
		t.Fatal("Open silently proceeded despite a failed state-dir adoption")
	} else if !strings.Contains(err.Error(), "adopt") {
		t.Fatalf("error lacks adoption context: %v", err)
	}
}
