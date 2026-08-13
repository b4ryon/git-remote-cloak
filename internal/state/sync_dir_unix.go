//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package state

import (
	"errors"
	"os"
)

// syncDir fsyncs a directory so a rename into it is durable across a crash:
// without it the renamed entry can be lost on power loss even though the
// file's own data was fsynced.
func syncDir(path string) error {
	f, err := os.Open(path) // #nosec G304 -- path is the per-remote state dir Root; never caller- or remote-controlled
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		return err
	}
	return f.Close()
}
