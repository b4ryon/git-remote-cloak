// Real-Keychain tests (run via `make test-darwin`): create/read/delete a
// generic password item in the login keychain. Item creation and read-back
// happen within the same binary, so the default app ACL allows silent
// access; the item is removed afterwards.

//go:build darwin && cgo && darwinkeystore

package keystore

import (
	"fmt"
	"os"
	"testing"
)

func TestKeychainRoundTrip(t *testing.T) {
	name := fmt.Sprintf("cloak-test-%d", os.Getpid())
	ref := "keychain:" + name
	t.Cleanup(func() { _ = Delete(ref) })

	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(ref, k); err != nil {
		t.Fatalf("keychain save: %v", err)
	}
	if err := Save(ref, k); err == nil {
		t.Fatal("keychain save overwrote an existing item")
	}
	got, err := Load(ref)
	if err != nil {
		t.Fatalf("keychain load: %v", err)
	}
	if got.Export() != k.Export() || got.ID() != k.ID() {
		t.Fatal("keychain round trip mismatch")
	}
	if err := Delete(ref); err != nil {
		t.Fatalf("keychain delete: %v", err)
	}
	if _, err := Load(ref); err == nil {
		t.Fatal("load succeeded after delete")
	}
}
