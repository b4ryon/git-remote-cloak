//go:build !windows

// Unix key-file mode validation.
package keystore

import (
	"fmt"
	"os"
)

func checkKeyFilePermissions(path string, fi os.FileInfo) error {
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; refusing group/world-accessible key files (want 0600)", path, perm)
	}
	return nil
}
