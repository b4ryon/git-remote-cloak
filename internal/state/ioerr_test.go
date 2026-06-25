// Unit tests asserting that filesystem failures on cloak's local bookkeeping
// files (the rollback pin, the applied-pack set) surface with the operation and
// file-name context attached and the underlying cause preserved, rather than as
// a bare syscall error, so a failed write/read of security-relevant state is
// attributable in the per-repo debug log.
package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateIOErrorsCarryContext(t *testing.T) {
	// dirAt plants a directory where a state file is expected, forcing a
	// deterministic, portable IO failure on the next read/write/remove of it
	// (ReadFile/OpenFile/Rename all fail against a directory; os.Remove fails on
	// a non-empty one).
	dirAt := func(t *testing.T, root, name string, nonEmpty bool) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if nonEmpty {
			if err := os.WriteFile(filepath.Join(p, "x"), []byte("x"), 0o600); err != nil {
				t.Fatalf("seed %s: %v", p, err)
			}
		}
	}
	// mustWrap asserts err is non-nil, carries the exact cloak operation context
	// wantPhrase (which a bare os.PathError -- whose text already embeds the file
	// path and errno -- does NOT contain, so this distinguishes the wrap), and
	// still unwraps to its underlying cause (wrapped with %w, not flattened).
	mustWrap := func(t *testing.T, err error, wantPhrase string) {
		t.Helper()
		if err == nil {
			t.Fatalf("expected an error carrying %q, got nil", wantPhrase)
		}
		if !strings.Contains(err.Error(), wantPhrase) {
			t.Fatalf("error %q is missing the %q operation context", err.Error(), wantPhrase)
		}
		if errors.Unwrap(err) == nil {
			t.Fatalf("error %q dropped its underlying cause (not wrapped with %%w)", err.Error())
		}
	}

	t.Run("read", func(t *testing.T) {
		d := openDir(t)
		dirAt(t, d.Root, appliedFile, false)
		_, err := d.AppliedSet()
		mustWrap(t, err, `read state file "`+appliedFile+`"`)
	})
	t.Run("write", func(t *testing.T) {
		d := openDir(t)
		dirAt(t, d.Root, pinFile, false)
		err := d.SavePin(Pin{Generation: 1, ManifestHash: strings.Repeat("ab", 32)})
		mustWrap(t, err, `write state file "`+pinFile+`"`)
	})
	t.Run("append", func(t *testing.T) {
		d := openDir(t)
		dirAt(t, d.Root, appliedFile, false)
		err := d.MarkApplied("p1")
		mustWrap(t, err, `append to state file "`+appliedFile+`"`)
	})
	t.Run("remove", func(t *testing.T) {
		d := openDir(t)
		dirAt(t, d.Root, pinFile, true) // non-empty: os.Remove fails ENOTEMPTY
		err := d.ClearPin()
		mustWrap(t, err, `remove state file "`+pinFile+`"`)
	})
}
