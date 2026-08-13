//go:build windows

package state

import (
	"os"

	"golang.org/x/sys/windows"
)

// Lock the first byte of the state lock file. A non-zero range is required by
// LockFileEx; requests without LOCKFILE_FAIL_IMMEDIATELY wait for the holder.
const stateLockBytes = 1

func lockFile(f *os.File) error {
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		stateLockBytes,
		0,
		&windows.Overlapped{},
	)
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0,
		stateLockBytes,
		0,
		&windows.Overlapped{},
	)
}
