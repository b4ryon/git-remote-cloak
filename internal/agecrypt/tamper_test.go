// Integrity-surfacing tests for the cloak decrypt path. age's STREAM binds each
// chunk's position into its nonce and flags the final chunk, so truncation,
// reorder, duplication, and splicing all fail authentication. These tests assert
// that those failures surface through our wrapper as a fail-closed cloakerr.Tamper
// and that NO authenticated-looking plaintext is released before the failure.
//
// The byte-surgery below depends on the age v1 payload layout (a 16-byte STREAM
// nonce, then 64 KiB+16 ciphertext chunks). Each case asserts the expected total
// length first, so a layout change fails loudly instead of passing falsely.
package agecrypt

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

const (
	streamNonceSize = 16           // age payload nonce prefix
	cipherChunk     = 64*1024 + 16 // 64 KiB plaintext + Poly1305 tag
)

func mustTamper(t *testing.T, err error, ctx string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: decrypt succeeded, want fail-closed", ctx)
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Tamper {
		t.Fatalf("%s: error not classified Tamper: %v", ctx, err)
	}
}

// payloadStart returns the offset of the binary payload (the STREAM nonce),
// i.e. the byte after the age header's "--- <mac>" line. Header body lines are
// base64 (no '-'), so "\n--- " uniquely marks the MAC line.
func payloadStart(t *testing.T, ct []byte) int {
	t.Helper()
	i := bytes.Index(ct, []byte("\n--- "))
	if i < 0 {
		t.Fatal("no MAC line found in age header")
	}
	nl := bytes.IndexByte(ct[i+1:], '\n')
	if nl < 0 {
		t.Fatal("MAC line not terminated")
	}
	return i + 1 + nl + 1
}

func TestDropFinalChunkFailsClosed(t *testing.T) {
	k := testKey(t)
	pt := make([]byte, 2*64*1024) // exactly two full chunks
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}
	ct, err := EncryptBytes(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	ps := payloadStart(t, ct)
	if got, want := len(ct), ps+streamNonceSize+2*cipherChunk; got != want {
		t.Fatalf("unexpected framing: ciphertext %d bytes, want %d (2 chunks)", got, want)
	}
	// Drop the entire final chunk at the boundary: the surviving chunk's
	// last-chunk flag is 0, so EOF arrives with no final chunk -> truncation.
	truncated := ct[:ps+streamNonceSize+cipherChunk]
	_, err = DecryptBytes(k, truncated)
	mustTamper(t, err, "drop-final-chunk")
}

func TestNoPartialPlaintextOnTamper(t *testing.T) {
	k := testKey(t)
	pt := make([]byte, 2*64*1024) // corrupt chunk 0 -> nothing should release
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}
	ct, err := EncryptBytes(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	ps := payloadStart(t, ct)
	mut := append([]byte(nil), ct...)
	mut[ps+streamNonceSize+10] ^= 0x01 // flip inside the first chunk's ciphertext

	dr, err := Decrypt(bytes.NewReader(mut), k)
	if err != nil {
		mustTamper(t, err, "first-chunk-corrupt (init)")
		return
	}
	buf := make([]byte, len(pt))
	total := 0
	for {
		n, err := dr.Read(buf[total:])
		total += n
		if err != nil {
			mustTamper(t, err, "first-chunk-corrupt (read)")
			break
		}
		if total >= len(pt) {
			t.Fatal("read the full plaintext from a corrupted stream")
		}
	}
	if total != 0 {
		t.Fatalf("released %d plaintext bytes before authentication failure on chunk 0", total)
	}
}

func TestChunkReorderDuplicateSpliceFailClosed(t *testing.T) {
	k := testKey(t)
	pt := make([]byte, 3*64*1024) // three full chunks
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}
	ct, err := EncryptBytes(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	ps := payloadStart(t, ct)
	base := ps + streamNonceSize
	if got, want := len(ct), base+3*cipherChunk; got != want {
		t.Fatalf("unexpected framing: ciphertext %d bytes, want %d (3 chunks)", got, want)
	}
	prefix := ct[:base] // header + STREAM nonce
	chunk := [3][]byte{
		ct[base : base+cipherChunk],
		ct[base+cipherChunk : base+2*cipherChunk],
		ct[base+2*cipherChunk : base+3*cipherChunk],
	}
	assemble := func(order ...int) []byte {
		out := append([]byte(nil), prefix...)
		for _, i := range order {
			out = append(out, chunk[i]...)
		}
		return out
	}
	cases := map[string][]byte{
		"swap-0-1":            assemble(1, 0, 2), // positional nonce mismatch
		"duplicate-0":         assemble(0, 0, 1, 2),
		"final-spliced-early": assemble(2, 0, 1), // last-flag chunk moved earlier
	}
	for name, mut := range cases {
		_, err := DecryptBytes(k, mut)
		mustTamper(t, err, name)
	}
}
