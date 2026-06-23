// Format-stability tests for the cloak/v1 stanza. These pin the on-host wire
// format so it cannot drift silently across refactors or age dependency bumps:
// a known-answer test for the HKDF wrap-key derivation (golden value computed
// INDEPENDENTLY via RFC 5869, not by this package) and a frozen-ciphertext
// regression guard that must keep decrypting forever under a fixed key.
package agecrypt

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// fixedKey is the deterministic master key 0x00..0x1f shared by the vectors.
func fixedKey(t *testing.T) keystore.Key {
	t.Helper()
	b := make([]byte, keystore.KeySize)
	for i := range b {
		b[i] = byte(i)
	}
	k, err := keystore.NewKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestDeriveWrapKeyKnownAnswer pins HKDF-SHA-256(master, salt, "cloak/v1 wrap").
// The expected value was computed independently with Python's stdlib (RFC 5869),
// NOT by this code, so it cross-checks our HKDF wiring rather than restating it.
// The wrap key is the first 32 bytes of the HKDF stream (the nonce is the next
// 12, read from the same stream):
//
//	ikm  = bytes(range(0,32)); salt = bytes(range(32,64)); info = b"cloak/v1 wrap"
//	prk  = hmac.new(salt, ikm, sha256).digest()
//	okm  = hmac.new(prk, info + b"\x01", sha256).digest()[:32]
//
// A drift in the hash, the "cloak/v1 wrap" label, the salt, or the HKDF
// secret/salt/info argument order breaks this test.
func TestDeriveWrapKeyKnownAnswer(t *testing.T) {
	salt := make([]byte, saltSize)
	for i := range salt {
		salt[i] = byte(32 + i)
	}
	const want = "f773f692ef650ba51c3b31a4ef94719f66d89af74a764d9d9660a504e7db470b"
	wk, _, err := deriveWrapKey(fixedKey(t), salt)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(wk); got != want {
		t.Fatalf("deriveWrapKey golden mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestStanzaFormatPinned freezes the stanza constants and the on-wire encoding
// of the salt argument (canonical unpadded base64 of exactly 32 bytes).
func TestStanzaFormatPinned(t *testing.T) {
	if StanzaType != "cloak/v1" {
		t.Fatalf("StanzaType = %q, want cloak/v1", StanzaType)
	}
	if saltSize != 32 {
		t.Fatalf("saltSize = %d, want 32", saltSize)
	}
	if wrapLabel != "cloak/v1 wrap" {
		t.Fatalf("wrapLabel = %q, want %q", wrapLabel, "cloak/v1 wrap")
	}

	ct, err := EncryptBytes(testKey(t), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(stanzaLine(t, ct)) // "-> cloak/v1 <salt-b64>"
	if len(fields) != 3 || fields[0] != "->" || fields[1] != StanzaType {
		t.Fatalf("unexpected stanza line fields: %q", fields)
	}
	arg := fields[2]
	if strings.ContainsRune(arg, '=') {
		t.Fatalf("salt arg is padded base64, want canonical RawStdEncoding: %q", arg)
	}
	salt, err := base64.RawStdEncoding.DecodeString(arg)
	if err != nil {
		t.Fatalf("salt arg is not RawStdEncoding base64: %v", err)
	}
	if len(salt) != saltSize {
		t.Fatalf("decoded salt = %d bytes, want %d", len(salt), saltSize)
	}
}

// frozenCiphertextB64 is a cloak/v1 file produced ONCE under fixedKey (master
// 0x00..0x1f), encrypting frozenPlaintext. If this stops decrypting, the
// on-host format changed. Regenerate only on an intentional format bump:
//
//	printf '%s' '<frozenPlaintext>' | git-cloak debug encrypt -key file:<fixedKeyFile> | base64
const (
	frozenPlaintext     = "cloak format-stability vector v1"
	frozenCiphertextB64 = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGNsb2FrL3YxIGF1a21QMk0vd0k1Ulp1VXdWYTBjTVY5bEc2SFAzbzhQNUZ3OFdabk41WXMKUS92VnRWaFpaaE11YVNxMkduakZkR1lrSUhjMlNTTWdJMjYwZDhDbU9PQQotLS0gMHZSWlpFTFNJTmFGRXRNR1FjWTM1eHZIdjZFMzRrQ0tFUzdvSk9reFJDawrkuk95opnNFXilkizJ9H0kwrGMi/FXo0SycP6JcXPoZEFu14xTnh3sw4P7wd2Vdz/vs7RQijRSJngEqukIJkgO"
)

// TestFrozenCiphertextDecrypts is the cross-version format regression guard: a
// captured ciphertext must keep decrypting under the same key, and must fail
// closed (Tamper) under any other key.
func TestFrozenCiphertextDecrypts(t *testing.T) {
	ct, err := base64.StdEncoding.DecodeString(frozenCiphertextB64)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptBytes(fixedKey(t), ct)
	if err != nil {
		t.Fatalf("frozen ciphertext failed to decrypt (wire-format drift?): %v", err)
	}
	if string(got) != frozenPlaintext {
		t.Fatalf("frozen plaintext mismatch: got %q want %q", got, frozenPlaintext)
	}
	if _, err := DecryptBytes(testKey(t), ct); err == nil {
		t.Fatal("frozen ciphertext decrypted under a different key")
	} else if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Tamper {
		t.Fatalf("wrong-key error not classified Tamper: %v", err)
	}
}
