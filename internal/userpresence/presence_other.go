// Stub user-presence check for platforms without LocalAuthentication
// (Linux, or darwin builds with cgo disabled): the check passes; the
// keystore at-rest protections are the operative control there.

//go:build !darwin || !cgo

package userpresence

func require(reason string) error { return nil }
