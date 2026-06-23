// Companion to foreign_test.go: besides the scrypt case, a standard age file
// encrypted to an X25519 recipient (the other built-in age recipient type, which
// a host could fabricate) must also be rejected as Tamper. cloak only opens its
// own cloak/v1 stanza, regardless of how well-formed the foreign age file is.
package agecrypt

import (
	"bytes"
	"testing"

	"filippo.io/age"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

func TestForeignX25519AgeFileRejected(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("a manifest forged with a standard X25519 recipient")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// cloak must refuse it: the stanza is X25519, not cloak/v1.
	_, err = DecryptBytes(testKey(t), buf.Bytes())
	if err == nil {
		t.Fatal("cloak decrypted a foreign (X25519) age file")
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Tamper {
		t.Fatalf("foreign X25519 age file not classified Tamper: %v", err)
	}
}
