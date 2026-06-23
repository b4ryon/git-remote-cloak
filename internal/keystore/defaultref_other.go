// Default key reference on platforms without Keychain support: the 0600
// key file, with disk encryption as the at-rest protection.

//go:build !darwin || !cgo

package keystore

// DefaultRef returns the platform default key reference.
func DefaultRef() string { return FileDefaultRef() }
