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
	t.Run("mark applied", func(t *testing.T) {
		d := openDir(t)
		dirAt(t, d.Root, appliedFile, false)
		err := d.MarkApplied("p1")
		// MarkApplied is a read-modify-rewrite; the planted directory fails its
		// read step. Match the shared `state file "applied"` context that both
		// the read and write wraps carry, without over-fitting to which sub-step.
		mustWrap(t, err, `state file "`+appliedFile+`"`)
	})
	t.Run("remove", func(t *testing.T) {
		d := openDir(t)
		dirAt(t, d.Root, pinFile, true) // non-empty: os.Remove fails ENOTEMPTY
		err := d.ClearPin()
		mustWrap(t, err, `remove state file "`+pinFile+`"`)
	})
	t.Run("write dir fsync", func(t *testing.T) {
		// Reaches writeStateFile's post-rename directory-fsync failure branch
		// (the iter1 write-path durability guard), the write-side twin of the
		// "remove dir fsync" case below. The temp file is written+fsynced and
		// renamed into place, but the dir fsync that would make that rename
		// crash-durable fails, and writeStateFile must surface that rather than
		// claim a durable save. As with the remove case, mode 0300 on the state
		// dir (write+execute, no read) lets the temp create (in the 0700 tmp/
		// subdir), traverse, and rename-into all succeed, yet makes syncDir's
		// os.Open of the dir fail EACCES; root bypasses the check, so skip there.
		if os.Geteuid() == 0 {
			t.Skip("running as root: directory read permission is not enforced")
		}
		d := openDir(t)
		if err := os.Chmod(d.Root, 0o300); err != nil {
			t.Fatalf("chmod root: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(d.Root, 0o700) }) // let TempDir cleanup recurse
		err := d.SavePin(Pin{Generation: 1, ManifestHash: strings.Repeat("ab", 32)})
		mustWrap(t, err, `write state file "`+pinFile+`"`)
		// The rename itself took effect (the file is in place); only its
		// durability could not be guaranteed, which is what was surfaced. Stat
		// needs only search permission on d.Root, which 0300 still grants.
		if _, statErr := os.Stat(filepath.Join(d.Root, pinFile)); statErr != nil {
			t.Fatalf("pin file should have been renamed into place before the fsync failure, stat err=%v", statErr)
		}
	})
	t.Run("remove dir fsync", func(t *testing.T) {
		// Reaches the OTHER removeStateFile failure branch: the post-remove
		// directory fsync (the iter3 durability guard), distinct from the
		// os.Remove failure the "remove" subtest above exercises. The pin file
		// is genuinely unlinked, but the dir fsync that would make that deletion
		// crash-durable fails, and removeStateFile must surface that rather than
		// claim a durable clear. Mode 0300 (write+execute, no read) on the state
		// dir lets os.Remove succeed yet makes syncDir's os.Open of the dir fail
		// EACCES; root bypasses the permission check, so skip there.
		if os.Geteuid() == 0 {
			t.Skip("running as root: directory read permission is not enforced")
		}
		d := openDir(t)
		if err := d.SavePin(Pin{Generation: 1, ManifestHash: strings.Repeat("ab", 32)}); err != nil {
			t.Fatalf("seed pin: %v", err)
		}
		if err := os.Chmod(d.Root, 0o300); err != nil {
			t.Fatalf("chmod root: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(d.Root, 0o700) }) // let TempDir cleanup recurse
		err := d.ClearPin()
		mustWrap(t, err, `remove state file "`+pinFile+`"`)
		// The unlink itself took effect (search permission still granted); only
		// its durability could not be guaranteed, which is what was surfaced.
		if _, statErr := os.Stat(filepath.Join(d.Root, pinFile)); !os.IsNotExist(statErr) {
			t.Fatalf("pin file should have been removed before the fsync failure, stat err=%v", statErr)
		}
	})
}
