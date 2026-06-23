// Default key reference on darwin cgo builds: the native Keychain, per the
// user decision that Keychain integration is a requirement on macOS.

//go:build darwin && cgo

package keystore

// DefaultRef returns the platform default key reference.
func DefaultRef() string { return "keychain:default" }
