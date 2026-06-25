// Regression tests for seed-remote leaf-IO error wrapping: a failed pack
// scratch-file open must carry operation context (not a bare os.PathError) and
// still unwrap to its cause, matching the engine's scratch-IO wrapping.
package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashPackFileOpenErrorCarriesContext(t *testing.T) {
	// A path inside a nonexistent directory makes os.Open fail with ENOENT
	// before HashObject is ever called, so the nil backend is never touched.
	missing := filepath.Join(t.TempDir(), "no-such-dir", "pack.age")

	_, err := hashPackFile(nil, missing)
	if err == nil {
		t.Fatal("hashPackFile on a missing path returned nil error")
	}
	if !strings.Contains(err.Error(), "open pack scratch file") {
		t.Fatalf("error lacks operation context: %q", err)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("error lacks the offending path %q: %q", missing, err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error does not unwrap to os.ErrNotExist: %q", err)
	}
}
