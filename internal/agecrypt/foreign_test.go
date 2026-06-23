// Tampering tests at the stanza layer: a blob validly encrypted to a
// recipient the attacker controls (a standard age scrypt file, NOT a cloak
// stanza) must be rejected as Tamper, and malformed cloak stanzas must be
// skipped rather than half-accepted. These pin that possession of the
// shared master key is the ONLY way to produce something cloak will open:
// AEAD authenticity rests on the stanza type plus the key, so a foreign
// age file the host could fabricate at will never decrypts here.
package agecrypt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"filippo.io/age"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

func TestForeignAgeFileRejected(t *testing.T) {
	// A normal age file encrypted to a passphrase the attacker knows.
	r, err := age.NewScryptRecipient("attacker-chosen-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(10) // keep the test fast
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("a manifest the host forged")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// cloak must refuse it: the stanza is scrypt, not cloak/v1.
	_, err = DecryptBytes(testKey(t), buf.Bytes())
	if err == nil {
		t.Fatal("cloak decrypted a foreign (scrypt) age file")
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Tamper {
		t.Fatalf("foreign age file not classified Tamper: %v", err)
	}
}

func TestUnwrapSkipsMalformedStanzas(t *testing.T) {
	id := identity{master: testKey(t)}
	goodSalt := base64.RawStdEncoding.EncodeToString(make([]byte, saltSize))
	cases := []struct {
		name    string
		stanzas []*age.Stanza
	}{
		{"wrong type", []*age.Stanza{{Type: "scrypt", Args: []string{goodSalt}, Body: []byte("x")}}},
		{"no args", []*age.Stanza{{Type: StanzaType, Args: nil, Body: []byte("x")}}},
		{"too many args", []*age.Stanza{{Type: StanzaType, Args: []string{goodSalt, "extra"}, Body: []byte("x")}}},
		{"non-base64 salt", []*age.Stanza{{Type: StanzaType, Args: []string{"!!!not base64!!!"}, Body: []byte("x")}}},
		{"short salt", []*age.Stanza{{Type: StanzaType, Args: []string{base64.RawStdEncoding.EncodeToString([]byte("tooshort"))}, Body: []byte("x")}}},
		{"no stanzas", nil},
	}
	for _, c := range cases {
		_, err := id.Unwrap(c.stanzas)
		if !errors.Is(err, age.ErrIncorrectIdentity) {
			t.Errorf("%s: Unwrap returned %v, want ErrIncorrectIdentity", c.name, err)
		}
	}
}

func TestUnwrapValidStanzaWrongKeyFails(t *testing.T) {
	// A well-formed cloak stanza produced under one key must not unwrap
	// under another: the AEAD open fails and the stanza is skipped.
	wrong := identity{master: testKey(t)}
	good := recipient{master: testKey(t)}
	stanzas, err := good.Wrap(make([]byte, 16)) // a dummy file key
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Unwrap(stanzas); !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("Unwrap under wrong key = %v, want ErrIncorrectIdentity", err)
	}
}
