//go:build windows

package state

import (
	"errors"

	"golang.org/x/sys/windows"
)

// syncDir opens the directory with GENERIC_WRITE and flushes its metadata.
// os.File.Sync opens directories read-only on Windows, but FlushFileBuffers
// requires a write-capable handle.
func syncDir(path string) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return err
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		if closeErr := windows.CloseHandle(h); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		return err
	}
	return windows.CloseHandle(h)
}
