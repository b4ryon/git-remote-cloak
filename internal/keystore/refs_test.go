// Unit tests for key reference handling: malformed and unknown schemes on
// Load/Save/Delete, the file Delete branch, home expansion, and Key
// edge cases (wrong size, zero key).
package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

func TestLoadSaveDeleteRejectMalformedRefs(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"nocolon", "bogus:whatever"} {
		if _, err := Load(ref); err == nil {
			t.Errorf("Load(%q) accepted a bad ref", ref)
		}
		if err := Save(ref, k); err == nil {
			t.Errorf("Save(%q) accepted a bad ref", ref)
		}
		if err := Delete(ref); err == nil {
			t.Errorf("Delete(%q) accepted a bad ref", ref)
		}
	}
}

func TestDeleteFileBackend(t *testing.T) {
	ref := "file:" + filepath.Join(t.TempDir(), "key")
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(ref, k); err != nil {
		t.Fatal(err)
	}
	if err := Delete(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ref); err == nil {
		t.Fatal("Load succeeded after Delete")
	}
	if err := Delete(ref); err == nil {
		t.Fatal("Delete of a missing key file reported success")
	}
}

// TestDeleteFileBackendErrorCarriesContext asserts the file Delete branch wraps
// its os.Remove failure with the same operation context and Kind as
// loadFile/saveFile, rather than leaking a bare os.PathError. Deleting a missing
// key file is the deterministic trigger; the assertion checks for the "delete
// key file" phrase the wrap adds (a bare os.Remove error never contains it, so
// this would false-pass against the unwrapped code) plus chain preservation and
// classification.
func TestDeleteFileBackendErrorCarriesContext(t *testing.T) {
	ref := "file:" + filepath.Join(t.TempDir(), "absent")
	err := Delete(ref)
	if err == nil {
		t.Fatal("Delete of a missing key file reported success")
	}
	if !strings.Contains(err.Error(), "delete key file") {
		t.Errorf("error %q lacks the 'delete key file' operation context", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %q does not unwrap to os.ErrNotExist", err)
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.KeyUnavailable {
		t.Errorf("error %q not classified KeyUnavailable (kind=%v ok=%v)", err, kind, ok)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("file:" + filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("Load of a missing key file succeeded")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	cases := map[string]string{
		"~":              home,
		"~/x/key":        filepath.Join(home, "x", "key"),
		"/abs/path":      "/abs/path",
		"~otheruser/key": "~otheruser/key",
		"relative/key":   "relative/key",
	}
	for in, want := range cases {
		if got := expandHome(in); got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewKeyWrongSize(t *testing.T) {
	if _, err := NewKey(make([]byte, 16)); err == nil {
		t.Fatal("NewKey accepted a 16-byte key")
	}
}

func TestZeroKey(t *testing.T) {
	var k Key
	if !k.IsZero() {
		t.Fatal("zero Key not IsZero")
	}
	if s := k.String(); !strings.Contains(s, "keyid=none") {
		t.Fatalf("zero key String = %q", s)
	}
}
