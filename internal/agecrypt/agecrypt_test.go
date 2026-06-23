// Unit tests for the cloak symmetric age stanza: round trips across chunk
// boundaries, fail-closed behavior on tamper/truncation/wrong key, and
// per-blob salt freshness.
package agecrypt

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

func testKey(t *testing.T) keystore.Key {
	t.Helper()
	k, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTripSizes(t *testing.T) {
	k := testKey(t)
	// Sizes straddle the age STREAM 64 KiB chunk boundary.
	for _, n := range []int{0, 1, 63, 64 * 1024, 64*1024 + 1, 1 << 20} {
		pt := make([]byte, n)
		if _, err := rand.Read(pt); err != nil {
			t.Fatal(err)
		}
		ct, err := EncryptBytes(k, pt)
		if err != nil {
			t.Fatalf("size %d: encrypt: %v", n, err)
		}
		got, err := DecryptBytes(k, ct)
		if err != nil {
			t.Fatalf("size %d: decrypt: %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: round trip mismatch", n)
		}
	}
}

func TestWrongKeyFailsClosed(t *testing.T) {
	ct, err := EncryptBytes(testKey(t), []byte("secret payload"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptBytes(testKey(t), ct)
	if err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Tamper {
		t.Fatalf("wrong-key error not classified Tamper: %v", err)
	}
}

func TestFlippedByteFailsClosed(t *testing.T) {
	k := testKey(t)
	pt := make([]byte, 200*1024)
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}
	ct, err := EncryptBytes(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	// Offsets cover the header (stanza args/body, MAC) and payload chunks.
	for _, off := range []int{10, 40, 80, len(ct) / 2, len(ct) - 1} {
		mut := append([]byte(nil), ct...)
		mut[off] ^= 0x01
		if _, err := DecryptBytes(k, mut); err == nil {
			t.Fatalf("flip at offset %d: decrypt succeeded on tampered ciphertext", off)
		} else if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Tamper {
			t.Fatalf("flip at offset %d: error not classified Tamper: %v", off, err)
		}
	}
}

func TestTruncationFailsClosed(t *testing.T) {
	k := testKey(t)
	pt := make([]byte, 200*1024)
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}
	ct, err := EncryptBytes(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	for _, drop := range []int{1, 16, 4096} {
		if _, err := DecryptBytes(k, ct[:len(ct)-drop]); err == nil {
			t.Fatalf("dropping %d trailing bytes: decrypt succeeded on truncated ciphertext", drop)
		}
	}
}

func TestSaltFreshness(t *testing.T) {
	k := testKey(t)
	pt := []byte("identical plaintext")
	ct1, err := EncryptBytes(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := EncryptBytes(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of identical plaintext produced identical ciphertext")
	}
	s1, s2 := stanzaLine(t, ct1), stanzaLine(t, ct2)
	if s1 == s2 {
		t.Fatalf("stanza salts identical across blobs: %q", s1)
	}
}

func TestStanzaTypeInHeader(t *testing.T) {
	ct, err := EncryptBytes(testKey(t), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stanzaLine(t, ct), StanzaType) {
		t.Fatalf("header stanza line missing type %q", StanzaType)
	}
}

// stanzaLine extracts the "-> cloak/v1 <salt>" line from the ASCII age header.
func stanzaLine(t *testing.T, ct []byte) string {
	t.Helper()
	for _, line := range strings.Split(string(ct[:min(len(ct), 2048)]), "\n") {
		if strings.HasPrefix(line, "-> "+StanzaType) {
			return line
		}
	}
	t.Fatal("no cloak stanza line found in header")
	return ""
}
