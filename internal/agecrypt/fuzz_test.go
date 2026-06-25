// Fuzz tests for the encryption round trip and the decrypt path's fail-closed
// contract. FuzzRoundTrip requires that any plaintext encrypted under a key
// decrypts back to the identical bytes. FuzzDecryptArbitrary feeds arbitrary
// bytes to the decrypt path (the untrusted remote-blob surface) and pins its
// fail-closed contract: any input that does not decrypt must surface as a
// cloakerr.Tamper alarm, release no plaintext, and never panic, and decryption
// must be deterministic. FuzzChunkReorderFailsClosed generalizes the fixed
// reorder/duplicate/splice unit cases: any rearrangement of genuine STREAM
// chunks must fail authentication (Tamper), so only the exact original chunk
// order decrypts. FuzzForeignAgeFileFailsClosed generalizes the fixed
// foreign-recipient unit cases: a well-formed age file forged to a recipient the
// host controls (not a cloak/v1 stanza) must fail closed as Tamper, pinning that
// possession of the master key is the only way to produce openable ciphertext.
package agecrypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// fuzzKey derives a deterministic master key from fuzz bytes so a crashing
// input reproduces exactly. keystore.NewKey requires exactly KeySize bytes, so
// short seeds zero-pad and long seeds truncate.
func fuzzKey(seed []byte) keystore.Key {
	b := make([]byte, keystore.KeySize)
	copy(b, seed)
	k, err := keystore.NewKey(b)
	if err != nil {
		panic(err) // unreachable: b is always exactly KeySize bytes
	}
	return k
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("key-seed"), []byte("plaintext payload"))
	f.Add([]byte(""), []byte(""))
	// A payload straddling the age STREAM 64 KiB chunk boundary.
	f.Add(bytes.Repeat([]byte{1}, keystore.KeySize), bytes.Repeat([]byte{0xAB}, 70*1024))

	f.Fuzz(func(t *testing.T, keySeed, plaintext []byte) {
		k := fuzzKey(keySeed)
		ct, err := EncryptBytes(k, plaintext)
		if err != nil {
			t.Fatalf("encrypt of %d-byte plaintext failed: %v", len(plaintext), err)
		}
		got, err := DecryptBytes(k, ct)
		if err != nil {
			t.Fatalf("decrypt of own ciphertext failed: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
		}
	})
}

// FuzzCrossKeyFailsClosed exercises cloak's central authenticity property: a
// genuine ciphertext produced under one master key must never open under a
// DIFFERENT master key. FuzzRoundTrip proves same-key decryption returns the
// plaintext; this proves wrong-key decryption fails closed -- it must return an
// error, never the plaintext, and never panic -- which is the guarantee that
// possession of the master key is the only way to read a blob. The unit tests
// spot-check this with a couple of fixed keys (agecrypt_test.go, format_test.go);
// fuzzing generalizes it across the whole key/plaintext space. When two seeds
// pad/truncate to identical key bytes the keys are equal, so the same input is a
// round trip and decryption must instead succeed.
func FuzzCrossKeyFailsClosed(f *testing.F) {
	f.Add([]byte("key-A"), []byte("key-B"), []byte("secret payload"))
	f.Add([]byte("same"), []byte("same"), []byte("identical keys must decrypt"))
	f.Add([]byte(""), []byte{0}, []byte("")) // "" and {0} both pad to the all-zero key
	// Distinct full-width keys over a payload straddling the STREAM chunk boundary.
	f.Add(bytes.Repeat([]byte{1}, keystore.KeySize), bytes.Repeat([]byte{2}, keystore.KeySize), bytes.Repeat([]byte{0xAB}, 70*1024))

	f.Fuzz(func(t *testing.T, seedA, seedB, plaintext []byte) {
		ka := fuzzKey(seedA)
		kb := fuzzKey(seedB)
		ct, err := EncryptBytes(ka, plaintext)
		if err != nil {
			t.Fatalf("encrypt under key A failed: %v", err)
		}
		got, err := DecryptBytes(kb, ct)
		if bytes.Equal(ka.Bytes(), kb.Bytes()) {
			// The two seeds collapsed to the same key, so this is really a round
			// trip: decryption must succeed and reproduce the plaintext.
			if err != nil {
				t.Fatalf("decrypt under an equal key failed: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("equal-key round trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
			}
			return
		}
		// Distinct keys: the AEAD wrap-key open must fail at the header, so
		// DecryptBytes must return an error. A nil error would mean a genuine
		// forgery (cryptographically infeasible) or a broken fail-closed path.
		if err == nil {
			t.Fatalf("ciphertext under key A decrypted under a distinct key B (got %d bytes)", len(got))
		}
	})
}

// FuzzTamperFailsClosed exercises cloak's AEAD integrity guarantee: a genuine
// ciphertext that is modified -- under the CORRECT key -- must fail to decrypt.
// age authenticates the whole header (the header MAC) and every payload chunk
// (per-chunk Poly1305), so flipping any single byte breaks authentication and
// DecryptBytes must return an error, never the original plaintext and never
// silently-altered plaintext. Where the flipped byte lands decides which
// classification path runs: a header byte fails in Decrypt ("decrypt header"
// tamper), a payload byte fails in tamperReader.Read ("decrypt payload"
// tamper) -- the exact cloakerr.Tamper surface (agecrypt.go) that no other
// fuzz test reaches. This is distinct from FuzzDecryptArbitrary (shapeless
// arbitrary bytes, not a tampered genuine ciphertext) and FuzzCrossKeyFailsClosed
// (a wrong key on an unmodified ciphertext): here the key is right and the
// ciphertext is a real one that has been tampered with. The one input that still decrypts is a
// no-op "tamper" (xor == 0 leaves the bytes unchanged), which must instead
// round-trip to the original plaintext.
func FuzzTamperFailsClosed(f *testing.F) {
	f.Add([]byte("key-seed"), []byte("secret payload"), uint32(0), byte(0xff))
	f.Add([]byte("seed"), []byte("data"), uint32(3), byte(0)) // no-op: must round-trip
	f.Add([]byte(""), []byte(""), uint32(0), byte(1))
	// Flip a byte deep in the payload of a >64 KiB blob, exercising the
	// tamperReader.Read (payload-chunk) path past the STREAM chunk boundary.
	f.Add(bytes.Repeat([]byte{1}, keystore.KeySize), bytes.Repeat([]byte{0xAB}, 70*1024), uint32(66000), byte(0x55))

	f.Fuzz(func(t *testing.T, keySeed, plaintext []byte, pos uint32, xor byte) {
		k := fuzzKey(keySeed)
		ct, err := EncryptBytes(k, plaintext)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		if len(ct) == 0 {
			return // unreachable: an age file always has a non-empty header
		}
		i := int(pos % uint32(len(ct)))
		tampered := append([]byte(nil), ct...)
		tampered[i] ^= xor
		got, err := DecryptBytes(k, tampered)
		if xor == 0 {
			// The XOR was a no-op, so tampered == ct: this is the genuine
			// ciphertext and must still decrypt to the original plaintext.
			if err != nil {
				t.Fatalf("no-op tamper broke decryption of own ciphertext: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("no-op tamper round trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
			}
			return
		}
		// xor != 0 changed byte i (b^nonzero != b), so the ciphertext is
		// genuinely modified and must fail closed. A nil error would mean an
		// AEAD forgery (cryptographically infeasible) or that integrity was not
		// enforced -- exactly the failure this guards against.
		if err == nil {
			t.Fatalf("tampered ciphertext (byte %d ^= %#x) decrypted without error (got %d bytes)", i, xor, len(got))
		}
	})
}

// FuzzStreamRoundTrip exercises the streaming Encrypt/Decrypt (io.WriteCloser /
// io.Reader) path the engine actually uses for packs, rather than the
// EncryptBytes/DecryptBytes wrappers FuzzRoundTrip covers. It drives the writer
// with fuzz-controlled write-chunk boundaries and reads the plaintext back
// through a fuzz-controlled buffer size: the age STREAM chunking must reassemble
// to the identical plaintext regardless of how Write calls and Reads are split.
func FuzzStreamRoundTrip(f *testing.F) {
	f.Add([]byte("key-seed"), []byte("plaintext payload"), uint16(1), uint16(1))
	f.Add([]byte(""), []byte(""), uint16(0), uint16(0))
	// A payload straddling the age STREAM 64 KiB chunk boundary, written and
	// read in odd-sized chunks that don't align to it.
	f.Add(bytes.Repeat([]byte{1}, keystore.KeySize), bytes.Repeat([]byte{0xAB}, 70*1024), uint16(4095), uint16(7000))

	f.Fuzz(func(t *testing.T, keySeed, plaintext []byte, writeChunk, readChunk uint16) {
		k := fuzzKey(keySeed)

		var buf bytes.Buffer
		w, err := Encrypt(&buf, k)
		if err != nil {
			t.Fatalf("encrypt writer init failed: %v", err)
		}
		wc := max(int(writeChunk), 1)
		for off := 0; off < len(plaintext); off += wc {
			end := min(off+wc, len(plaintext))
			if _, err := w.Write(plaintext[off:end]); err != nil {
				t.Fatalf("streaming write of [%d:%d] failed: %v", off, end, err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("closing encrypt writer failed: %v", err)
		}

		r, err := Decrypt(bytes.NewReader(buf.Bytes()), k)
		if err != nil {
			t.Fatalf("decrypt of own ciphertext failed: %v", err)
		}
		// Read back through a fixed-size buffer so readChunk genuinely drives the
		// read sizes; a bytes.Buffer destination via io.Copy would take the
		// ReaderFrom fast path and ignore the chunking entirely.
		rbuf := make([]byte, max(int(readChunk), 1))
		var got []byte
		for {
			n, err := r.Read(rbuf)
			got = append(got, rbuf[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("streaming read back failed: %v", err)
			}
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("stream round trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
		}
	})
}

// FuzzUnwrapStanza fuzzes cloak's own symmetric-stanza unwrap parser in
// isolation. tryUnwrapStanza reads the wrap salt out of the age header stanza,
// which is attacker-controlled remote-blob data, so it must never panic on a
// malformed Type, salt arg, or body, and must report success only for a
// well-formed cloak stanza whose AEAD body actually opens. FuzzDecryptArbitrary
// reaches this code only transitively, and only when the fuzzer manages to
// synthesize a parseable age header around it; fuzzing the stanza directly
// drives the salt base64-decode, the saltSize length check, and the AEAD-open
// branch regardless of the surrounding age framing. This is the highest-risk
// hand-written parser in the crypto layer (the symmetric stanza is cloak's, not
// upstream age's).
func FuzzUnwrapStanza(f *testing.F) {
	// A genuine cloak stanza, so the fuzzer can mutate a valid salt and body.
	if st, err := (recipient{fuzzKey([]byte("seed"))}).Wrap(bytes.Repeat([]byte{7}, 16)); err == nil && len(st) == 1 {
		f.Add([]byte("seed"), st[0].Type, st[0].Args[0], st[0].Body)
	}
	validSalt := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0}, saltSize))
	f.Add([]byte("seed"), StanzaType, validSalt, []byte("body that will not open"))
	f.Add([]byte("seed"), "other/type", validSalt, []byte("body")) // wrong stanza type
	f.Add([]byte("seed"), StanzaType, "AAAA", []byte("body"))      // salt decodes to 3 bytes != saltSize
	f.Add([]byte("seed"), StanzaType, "!!!not base64!!!", []byte("body"))
	f.Add([]byte(""), "", "", []byte(""))

	f.Fuzz(func(t *testing.T, keySeed []byte, stanzaType, saltArg string, body []byte) {
		i := identity{fuzzKey(keySeed)}
		s := &age.Stanza{Type: stanzaType, Args: []string{saltArg}, Body: body}
		fileKey, ok := i.tryUnwrapStanza(s)
		if !ok {
			// Every rejection branch must fail closed without leaking key material.
			if fileKey != nil {
				t.Fatalf("tryUnwrapStanza(%q) returned ok=false but a non-nil file key", stanzaType)
			}
			return // a rejected stanza is fine; the requirement is no panic
		}
		// A successful unwrap implies every structural precondition held: the
		// cloak stanza type and a salt arg that base64-decoded to exactly
		// saltSize bytes. Anything else opening would be a parser bug.
		if s.Type != StanzaType {
			t.Fatalf("unwrapped a stanza of type %q, want %q", s.Type, StanzaType)
		}
		salt, err := base64.RawStdEncoding.DecodeString(saltArg)
		if err != nil || len(salt) != saltSize {
			t.Fatalf("unwrapped despite malformed salt arg %q (decode err %v, len %d, want %d)",
				saltArg, err, len(salt), saltSize)
		}
		if fileKey == nil {
			t.Fatalf("successful unwrap returned a nil file key")
		}
	})
}

// FuzzStanzaWrapRoundTrip fuzzes cloak's symmetric stanza key-wrap round trip
// directly: recipient.Wrap seals a file key under a per-blob (key, nonce)
// derived by HKDF from the master key and a fresh random salt, and
// identity.Unwrap recovers it. This is the encode-side counterpart to
// FuzzUnwrapStanza, which fuzzes only the decode/open side on adversarial
// stanzas. The whole-file path (FuzzRoundTrip via EncryptBytes/DecryptBytes)
// does drive Wrap, but only with age's fixed random 16-byte file key and only
// buried inside the full age framing, so the hand-written seal path is never
// exercised over arbitrary file-key bytes in isolation -- the same reason
// tryUnwrapStanza warranted its own direct fuzz target. The pinned invariants:
// for any master key and any file-key bytes, Wrap must emit exactly one cloak
// stanza carrying a single well-formed saltSize-byte base64 salt, Unwrap under
// the wrapping key must return the identical file key, and Unwrap under a
// distinct key must fail closed (an error, never the file key). When the two
// seeds pad/truncate to the same key bytes the keys are equal, so that case is
// really the same-key round trip and must instead succeed.
func FuzzStanzaWrapRoundTrip(f *testing.F) {
	f.Add([]byte("master-A"), []byte("master-B"), []byte("0123456789abcdef")) // 16-byte file key, age's shape
	f.Add([]byte("same"), []byte("same"), []byte("equal keys must unwrap"))   // equal keys: a round trip
	f.Add([]byte(""), []byte{0}, []byte(""))                                  // "" and {0} pad to the all-zero key
	f.Add(bytes.Repeat([]byte{1}, keystore.KeySize), bytes.Repeat([]byte{2}, keystore.KeySize), bytes.Repeat([]byte{0xAB}, 64))

	f.Fuzz(func(t *testing.T, seedA, seedB, fileKey []byte) {
		ka := fuzzKey(seedA)
		kb := fuzzKey(seedB)

		stanzas, err := recipient{ka}.Wrap(fileKey)
		if err != nil {
			t.Fatalf("Wrap of %d-byte file key failed: %v", len(fileKey), err)
		}
		// Wrap always emits exactly one cloak stanza with a single salt arg that
		// base64-decodes to a full-width salt: anything else and the matching
		// tryUnwrapStanza structural checks could never open it.
		if len(stanzas) != 1 {
			t.Fatalf("Wrap returned %d stanzas, want 1", len(stanzas))
		}
		st := stanzas[0]
		if st.Type != StanzaType {
			t.Fatalf("Wrap produced stanza type %q, want %q", st.Type, StanzaType)
		}
		if len(st.Args) != 1 {
			t.Fatalf("Wrap produced %d salt args, want 1", len(st.Args))
		}
		salt, derr := base64.RawStdEncoding.DecodeString(st.Args[0])
		if derr != nil || len(salt) != saltSize {
			t.Fatalf("Wrap produced malformed salt arg %q (decode err %v, len %d, want %d)",
				st.Args[0], derr, len(salt), saltSize)
		}

		// The wrapping key must recover the exact file-key bytes.
		got, err := identity{ka}.Unwrap([]*age.Stanza{st})
		if err != nil {
			t.Fatalf("Unwrap under the wrapping key failed: %v", err)
		}
		if !bytes.Equal(got, fileKey) {
			t.Fatalf("wrap round trip mismatch: got %d bytes, want %d", len(got), len(fileKey))
		}

		got2, err2 := identity{kb}.Unwrap([]*age.Stanza{st})
		if bytes.Equal(ka.Bytes(), kb.Bytes()) {
			// The two seeds collapsed to the same key, so this is really the
			// wrapping key again: Unwrap must succeed and reproduce the file key.
			if err2 != nil {
				t.Fatalf("Unwrap under an equal key failed: %v", err2)
			}
			if !bytes.Equal(got2, fileKey) {
				t.Fatalf("equal-key wrap round trip mismatch: got %d bytes, want %d", len(got2), len(fileKey))
			}
			return
		}
		// Distinct keys: the AEAD open of the wrapped file key must fail, so
		// Unwrap returns ErrIncorrectIdentity. A nil error would mean a genuine
		// forgery (cryptographically infeasible) or a broken fail-closed path.
		if err2 == nil {
			t.Fatalf("stanza wrapped under key A unwrapped under a distinct key B (got %d bytes)", len(got2))
		}
	})
}

// fixedSalt maps fuzz bytes to a salt of exactly saltSize bytes (zero-padding
// short seeds, truncating long ones), matching the only salt width that ever
// reaches deriveWrapKey in production: Wrap mints a saltSize crypto/rand salt
// and Unwrap rejects any decoded length != saltSize before calling. Comparing
// these fixed-width salts (rather than the raw seeds) is what keeps the
// sensitivity invariant sound -- see FuzzDeriveWrapKey.
func fixedSalt(seed []byte) []byte {
	s := make([]byte, saltSize)
	copy(s, seed)
	return s
}

// FuzzDeriveWrapKey fuzzes deriveWrapKey, the HKDF core of the symmetric
// stanza: it reads the per-blob wrap key AND nonce from a single
// HKDF-SHA-256 stream keyed by the master key and salted by the stanza salt.
// Three properties carry cloak's nonce-derivation design and are pinned here
// directly rather than only indirectly through Wrap/Unwrap:
//
//   - Length split: wk must be exactly chacha20poly1305.KeySize bytes and
//     nonce exactly NonceSize bytes. The split is wk=out[:KeySize],
//     nonce=out[KeySize:], so a change to either constant would silently
//     misalign the key/nonce boundary; this pins the produced lengths over any
//     salt length (raw saltA), which also pins no-panic robustness on the odd
//     lengths production never passes.
//   - Determinism: the nonce is derived, not stored (package doc), so unwrap
//     re-derives it from the salt on every read. deriveWrapKey must therefore
//     return identical (wk, nonce) for identical (master, salt) -- if it ever
//     became non-deterministic, every decrypt would fail.
//   - Salt sensitivity (anti-nonce-reuse): the package doc calls a salt
//     collision catastrophic -- two blobs sharing a salt would reuse one
//     (key, nonce) pair over different file keys. So for the SAME master,
//     distinct salts must never yield the SAME (wk, nonce) pair. This is
//     asserted over fixedSalt-normalized (saltSize-width) salts, the only width
//     production ever derives under: HMAC zero-pads its key to the 64-byte
//     block, so all-zero salts of DIFFERENT lengths (e.g. "" vs {0}) are
//     HMAC-key-equivalent and legitimately derive the same pair -- a benign
//     HMAC property, not reuse, and unreachable in production where every salt
//     is exactly saltSize bytes. Among saltSize-width salts distinct values
//     never collide. Equal salt bytes are the genuine collision case and must
//     reproduce the pair.
func FuzzDeriveWrapKey(f *testing.F) {
	f.Add([]byte("master-seed"), []byte("salt-A"), []byte("salt-B"))
	f.Add([]byte("same"), []byte("identical"), []byte("identical")) // equal salts: same pair
	f.Add([]byte(""), []byte{}, []byte{0})                          // HMAC-equivalent zero salts: same pair
	f.Add(bytes.Repeat([]byte{1}, keystore.KeySize), bytes.Repeat([]byte{2}, 100), []byte("short"))

	f.Fuzz(func(t *testing.T, masterSeed, saltA, saltB []byte) {
		master := fuzzKey(masterSeed)

		// Length and robustness over the RAW (arbitrary-length) salt: the output
		// widths must hold and the derivation must not panic for any salt length.
		wkRaw, nonceRaw, err := deriveWrapKey(master, saltA)
		if err != nil {
			t.Fatalf("deriveWrapKey(raw saltA, len %d) failed: %v", len(saltA), err)
		}
		if len(wkRaw) != chacha20poly1305.KeySize {
			t.Fatalf("wrap key length = %d, want %d", len(wkRaw), chacha20poly1305.KeySize)
		}
		if len(nonceRaw) != chacha20poly1305.NonceSize {
			t.Fatalf("nonce length = %d, want %d", len(nonceRaw), chacha20poly1305.NonceSize)
		}

		// Sensitivity over the production salt width. fixedSalt maps each seed to
		// exactly saltSize bytes, so the comparison matches what production derives
		// under and avoids the cross-length HMAC zero-padding equivalence.
		psA, psB := fixedSalt(saltA), fixedSalt(saltB)
		wkA, nonceA, err := deriveWrapKey(master, psA)
		if err != nil {
			t.Fatalf("deriveWrapKey(psA) failed: %v", err)
		}

		// Determinism: unwrap re-derives the nonce from the salt, so a second
		// derivation under the identical (master, salt) must reproduce the pair.
		wkA2, nonceA2, err := deriveWrapKey(master, psA)
		if err != nil {
			t.Fatalf("re-deriveWrapKey(psA) failed: %v", err)
		}
		if !bytes.Equal(wkA, wkA2) || !bytes.Equal(nonceA, nonceA2) {
			t.Fatalf("deriveWrapKey is non-deterministic for a fixed (master, salt)")
		}

		wkB, nonceB, err := deriveWrapKey(master, psB)
		if err != nil {
			t.Fatalf("deriveWrapKey(psB) failed: %v", err)
		}
		samePair := bytes.Equal(wkA, wkB) && bytes.Equal(nonceA, nonceB)
		if bytes.Equal(psA, psB) {
			// Identical saltSize salt bytes are the genuine collision: the same
			// master and salt must reproduce the same (key, nonce), or determinism
			// is broken.
			if !samePair {
				t.Fatalf("equal salts produced different (key, nonce) under one master")
			}
			return
		}
		// Distinct saltSize salts must not collide onto the same (key, nonce): that
		// pair is exactly the catastrophic ChaCha20-Poly1305 reuse the salt width
		// exists to prevent (44 bytes of HKDF output, so an honest collision is
		// ~2^-352).
		if samePair {
			t.Fatalf("distinct saltSize salts derived the SAME (key, nonce) pair under one master")
		}
	})
}

// FuzzTruncationFailsClosed exercises cloak's truncation-resistance guarantee: a
// genuine ciphertext cut short at any length must fail to decrypt, never
// yielding a partial-but-accepted plaintext. This is the failure mode a
// withholding or buggy host produces by serving an incomplete manifest.age or
// pack blob, and it is distinct from every other agecrypt fuzz target:
// FuzzTamperFailsClosed flips one byte but PRESERVES the length,
// FuzzCrossKeyFailsClosed uses a wrong key on the FULL ciphertext, and
// FuzzDecryptArbitrary feeds shapeless arbitrary bytes -- none cuts a
// genuine ciphertext short. age's STREAM construction marks the final chunk with
// a distinct nonce, so dropping any trailing byte breaks authentication of
// whatever the decryptor would otherwise treat as the last chunk.
//
// Two paths carry the guarantee and are both pinned:
//   - The byte path (DecryptBytes, the manifest read): must return an error for
//     any strict truncation. It already discards the io.ReadAll partial on error,
//     so a truncated manifest can never be parsed.
//   - The streaming path (Decrypt -> io.Reader, the pack read piped to git
//     index-pack): reading a truncated stream to completion must terminate in a
//     non-EOF error, NEVER a clean EOF. A clean EOF would mean the consumer
//     accepted a truncated pack as complete. (The reader may deliver a partial
//     prefix before erroring -- e.g. a complete first chunk of a multi-chunk
//     blob -- which is fine because the terminal error rejects the whole stream.)
//
// n is taken modulo len(ct) so it is always a STRICT truncation (n < len(ct));
// the genuine, untruncated ciphertext is round-tripped unconditionally first to
// anchor the test, so the success path is exercised on every input regardless.
func FuzzTruncationFailsClosed(f *testing.F) {
	f.Add([]byte("key-seed"), []byte("secret manifest payload"), uint32(0))
	f.Add([]byte("seed"), []byte("data"), uint32(1))
	f.Add([]byte(""), []byte(""), uint32(0)) // empty plaintext: header-only edge
	// A >64 KiB blob truncated inside its second STREAM chunk, so the reader
	// delivers a complete first chunk and must still terminate in an error.
	f.Add(bytes.Repeat([]byte{1}, keystore.KeySize), bytes.Repeat([]byte{0xAB}, 70*1024), uint32(65536+100))

	f.Fuzz(func(t *testing.T, keySeed, plaintext []byte, truncLen uint32) {
		k := fuzzKey(keySeed)
		ct, err := EncryptBytes(k, plaintext)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		if len(ct) == 0 {
			return // unreachable: an age file always has a non-empty header
		}
		// Anchor: the genuine, untruncated ciphertext must round-trip. This keeps
		// the success path exercised on every input and guards against a test that
		// only ever rejects.
		if got, derr := DecryptBytes(k, ct); derr != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("genuine ciphertext failed to round-trip (err %v, got %d bytes, want %d)", derr, len(got), len(plaintext))
		}

		// Strict truncation: n in [0, len(ct)-1]. Every such prefix is missing at
		// least the final byte, so authentication of the (real or apparent) last
		// chunk must fail.
		n := int(truncLen % uint32(len(ct)))
		short := ct[:n]

		// Byte path: must fail closed (an error, so DecryptBytes returns no bytes).
		// A nil error would mean a truncated manifest decrypted into a usable value.
		if _, derr := DecryptBytes(k, short); derr == nil {
			t.Fatalf("truncated ciphertext (n=%d of %d) decrypted without error on the byte path", n, len(ct))
		}

		// Streaming path: a header failure is an acceptable fail-closed outcome; if
		// the header parses, draining the reader must terminate in an error rather
		// than a clean EOF. io.Copy returns a nil error only on a clean EOF, so a
		// nil here means the truncated stream was accepted as complete -- the harm.
		// io.Discard.ReadFrom drives r.Read directly, so tamperReader's payload-error
		// mapping is genuinely exercised (no ReaderFrom shortcut bypasses it).
		if r, serr := Decrypt(bytes.NewReader(short), k); serr == nil {
			if _, cerr := io.Copy(io.Discard, r); cerr == nil {
				t.Fatalf("truncated ciphertext (n=%d of %d) streamed to a clean EOF; truncation undetected", n, len(ct))
			}
		}
	})
}

// FuzzExtensionFailsClosed is the byte-level mirror of FuzzTruncationFailsClosed:
// it appends arbitrary non-empty trailing bytes AFTER a complete genuine
// ciphertext and requires the decrypt path to fail closed rather than silently
// ignore them. age's STREAM construction marks the final chunk with a distinct
// nonce flag, so once the reader has consumed the final chunk it must reject any
// remaining bytes ("trailing data after end of encrypted file") instead of
// returning a clean EOF -- otherwise a host could pad a genuine manifest.age or
// pack blob with extra bytes (smuggling data, or inflating the recorded pack
// size) and have it accepted as complete.
//
// This is distinct from every other agecrypt fail-closed fuzzer: truncation cuts
// a strict PREFIX (n < len(ct)), FuzzChunkReorderFailsClosed rearranges whole
// chunk-aligned segments, FuzzTamperFailsClosed flips one byte length-preserving,
// and FuzzDecryptArbitrary feeds shapeless bytes -- none appends byte-level
// trailing garbage to an otherwise-complete ciphertext. Together with truncation
// it brackets the contract that ANY byte-length change to a genuine ciphertext is
// detected.
//
// Both production paths are pinned, exactly as truncation does:
//   - The byte path (DecryptBytes, the manifest read): must fail closed. Because
//     the genuine header is intact at the front, the header always parses, so the
//     failure surfaces from the payload reader as cloakerr.Tamper.
//   - The streaming path (Decrypt -> io.Reader, the pack read piped to git
//     index-pack): draining the reader must terminate in a Tamper error, never a
//     clean EOF (which would mean the padded stream was accepted as complete).
//
// The oracle is sound with no false-positive risk: appended arbitrary bytes can
// never form a valid continuation of the AEAD STREAM without the file key
// (~2^-128 to synthesize), so a non-empty extension always fails closed. The
// genuine ciphertext is round-tripped unconditionally first to anchor the success
// path on every input; an empty trailing slice is a no-op and returns early.
func FuzzExtensionFailsClosed(f *testing.F) {
	f.Add([]byte("key-seed"), []byte("secret manifest payload"), []byte{0x00})
	f.Add([]byte("seed"), []byte("data"), []byte("X"))
	f.Add([]byte(""), []byte(""), []byte{0xAB}) // empty plaintext: header-only genuine ct
	f.Add([]byte("k"), []byte("p"), []byte{})   // empty trailing: no-op, anchor only
	// Long zero-byte trailing that could superficially resemble another chunk.
	f.Add([]byte("k2"), []byte("payload"), bytes.Repeat([]byte{0}, 200))
	// A genuine ciphertext whose final STREAM chunk is FULL-size (exactly 64 KiB
	// plaintext): age cannot use a short read to detect the end here and must rely
	// on the final-flag plus trailing-data detection -- the case most likely to
	// expose a silent-accept bug.
	f.Add(bytes.Repeat([]byte{2}, keystore.KeySize), bytes.Repeat([]byte{0xCD}, 64*1024), []byte{0x99})
	// Trailing appended past a multi-chunk (>64 KiB) blob.
	f.Add(bytes.Repeat([]byte{1}, keystore.KeySize), bytes.Repeat([]byte{0xAB}, 70*1024), []byte("trailing"))

	f.Fuzz(func(t *testing.T, keySeed, plaintext, trailing []byte) {
		k := fuzzKey(keySeed)
		ct, err := EncryptBytes(k, plaintext)
		if err != nil {
			t.Fatalf("encrypt of %d-byte plaintext failed: %v", len(plaintext), err)
		}
		// Anchor: the genuine, unextended ciphertext must round-trip. This keeps the
		// success path exercised on every input and guards against a test that only
		// ever rejects.
		if got, derr := DecryptBytes(k, ct); derr != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("genuine ciphertext failed to round-trip (err %v, got %d bytes, want %d)", derr, len(got), len(plaintext))
		}
		if len(trailing) == 0 {
			return // an empty extension equals the genuine ciphertext; the anchor covered it
		}

		extended := append(append([]byte(nil), ct...), trailing...)

		// Byte path: must fail closed as Tamper (the intact header parses, so the
		// failure surfaces from the payload reader). A success would mean a padded
		// manifest decrypted into a usable value with the extra bytes ignored.
		_, derr := DecryptBytes(k, extended)
		mustTamper(t, derr, fmt.Sprintf("extension byte path: +%d trailing bytes on %d-byte ct", len(trailing), len(ct)))

		// Streaming path: the header parses (genuine prefix intact), so draining the
		// reader must terminate in a Tamper error rather than a clean EOF. io.Discard
		// drives r.Read directly, so tamperReader's payload-error mapping is exercised.
		r, serr := Decrypt(bytes.NewReader(extended), k)
		if serr != nil {
			return // a header-level fail-closed is also acceptable (not expected here)
		}
		_, cerr := io.Copy(io.Discard, r)
		mustTamper(t, cerr, fmt.Sprintf("extension stream path: +%d trailing bytes on %d-byte ct", len(trailing), len(ct)))
	})
}

// FuzzChunkReorderFailsClosed exercises cloak's resistance to STREAM chunk
// rearrangement: age binds each 64 KiB chunk's position into its nonce (an
// 11-byte counter plus a 1-byte final-chunk flag), so reordering, duplicating,
// dropping, or splicing whole authenticated chunks must fail authentication.
// This is a fail-closed mode distinct from the other decrypt fuzzers:
// FuzzTamperFailsClosed flips a single byte in place (length-preserving),
// FuzzTruncationFailsClosed cuts a strict prefix, FuzzCrossKeyFailsClosed uses
// a wrong key on the whole ciphertext, and FuzzDecryptArbitrary feeds shapeless
// bytes -- none rearranges genuine chunks. It generalizes the three fixed
// reorderings in TestChunkReorderDuplicateSpliceFailClosed to an arbitrary
// chunk-index sequence over a 1-to-3-chunk ciphertext.
//
// The reassembly always preserves the genuine header + STREAM nonce prefix
// (ct[:base]) verbatim, so age.Decrypt's header parse always succeeds and every
// failure is a payload chunk-auth failure routed through tamperReader -> Tamper
// (agecrypt.go) -- making mustTamper a sound oracle. Each chunk is sealed under
// a distinct positional nonce, so chunk bytes differ by position and the
// reassembled bytes equal the genuine ciphertext iff the order is the exact
// identity [0,1,..,N-1]; any other sequence yields bytes that cannot
// authenticate, so the success-iff-identical / fail-closed split is exact with
// no false positive (no rearrangement legitimately decrypts).
func FuzzChunkReorderFailsClosed(f *testing.F) {
	// The unit test's three fixed cases over a 3-chunk ciphertext (nSel=2 ->
	// nChunks=3): positional swap, duplication, and an early-spliced final chunk.
	f.Add([]byte("key-seed"), byte(2), byte(0xAB), []byte{1, 0, 2})
	f.Add([]byte("key-seed"), byte(2), byte(0xAB), []byte{0, 0, 1, 2})
	f.Add([]byte("key-seed"), byte(2), byte(0xAB), []byte{2, 0, 1})
	// Identity reconstructions (success path) at 1 and 2 chunks.
	f.Add([]byte(""), byte(0), byte(0x00), []byte{0})
	f.Add([]byte("seed"), byte(1), byte(0x00), []byte{0, 1})
	// Single-chunk duplication, empty order (no chunks), and a dropped chunk.
	f.Add([]byte("k"), byte(0), byte(0x55), []byte{0, 0})
	f.Add([]byte("k2"), byte(1), byte(0x10), []byte{})
	f.Add([]byte("k3"), byte(2), byte(0x77), []byte{0, 1})

	f.Fuzz(func(t *testing.T, keySeed []byte, nSel, fill byte, order []byte) {
		k := fuzzKey(keySeed)
		nChunks := int(nSel%3) + 1 // 1, 2, or 3 whole STREAM chunks

		// Plaintext is an exact multiple of the 64 KiB chunk size, so every chunk
		// is a full cipherChunk and the payload splits cleanly with no partial or
		// extra empty trailing chunk (matching the unit-test layout assumption).
		pt := bytes.Repeat([]byte{fill}, nChunks*64*1024)
		ct, err := EncryptBytes(k, pt)
		if err != nil {
			t.Fatalf("encrypt of %d-chunk plaintext failed: %v", nChunks, err)
		}

		// Anchor: the genuine ciphertext must round-trip on every input, keeping
		// the success path exercised even when the fuzzer rarely picks the exact
		// identity order for nChunks>1.
		if got, derr := DecryptBytes(k, ct); derr != nil || !bytes.Equal(got, pt) {
			t.Fatalf("genuine %d-chunk ciphertext failed to round-trip: err %v, got %d want %d", nChunks, derr, len(got), len(pt))
		}

		ps := payloadStart(t, ct)
		base := ps + streamNonceSize
		if got, want := len(ct), base+nChunks*cipherChunk; got != want {
			t.Fatalf("unexpected age framing: ciphertext %d bytes, want %d (%d chunks); layout assumption broke", got, want, nChunks)
		}
		prefix := ct[:base] // header + STREAM nonce, always preserved verbatim
		chunk := make([][]byte, nChunks)
		for c := range chunk {
			chunk[c] = ct[base+c*cipherChunk : base+(c+1)*cipherChunk]
		}

		// Reassemble the payload from the fuzzed chunk-index sequence: a shorter
		// order drops chunks, a longer one duplicates/splices, and a permutation
		// reorders them.
		assembled := append([]byte(nil), prefix...)
		for _, b := range order {
			assembled = append(assembled, chunk[int(b)%nChunks]...)
		}

		if bytes.Equal(assembled, ct) {
			return // identity reconstruction; the anchor above already proved it round-trips
		}
		// Any structural rearrangement (reorder, duplicate, drop, splice) yields
		// bytes that cannot authenticate and must fail closed as Tamper.
		_, derr := DecryptBytes(k, assembled)
		mustTamper(t, derr, fmt.Sprintf("chunk-reorder order=%v nChunks=%d", order, nChunks))
	})
}

// FuzzDecryptArbitrary feeds arbitrary attacker-controlled bytes to the decrypt
// path -- the untrusted remote-blob surface (manifest.age and pack blobs served
// by the host) -- and pins its fail-closed contract. The original iteration-1
// target asserted only no-panic; the load-bearing guarantee it left unchecked is
// the classification: DecryptBytes never partially succeeds and never
// misclassifies a failure. For any input that does NOT decrypt, the error must
// be classified cloakerr.Tamper (so a corrupt, withheld, or forged blob raises
// the integrity alarm rather than masquerading as a retryable transport error or
// an unclassified bare error, either of which would let a hostile host be
// silently retried instead of escalated) AND no plaintext may be released. Every
// DecryptBytes error routes through tamper() -> cloakerr.Tamper -- the header
// parse in Decrypt and the payload chunks in tamperReader -- so the property
// holds for every failing input. For the rare input that DOES decrypt (a genuine
// ciphertext, e.g. the seed), decryption is deterministic.
//
// This is the arbitrary-bytes complement to the structured fail-closed targets
// (FuzzTamper/Truncation/Extension/ChunkReorder/CrossKey/ForeignAgeFile), each
// of which pins one specific attack shape; this one pins the universal "anything
// that fails, fails as Tamper with no leak" property over shapeless input.
func FuzzDecryptArbitrary(f *testing.F) {
	// Seed with a genuine ciphertext (so the fuzzer can mutate a valid header and
	// reach both the header-parse and payload-chunk failure paths) and with
	// plainly invalid input.
	if ct, err := EncryptBytes(fuzzKey([]byte("seed")), []byte("hello")); err == nil {
		f.Add([]byte("seed"), ct)
	}
	// A genuine MULTI-chunk ciphertext truncated inside its second STREAM chunk:
	// io.ReadAll delivers the complete first chunk's plaintext and THEN fails to
	// authenticate the missing final chunk. This is the partial-delivery error
	// path, which must surface as Tamper AND release none of the delivered bytes;
	// the arbitrary-bytes fuzzer cannot forge a multi-chunk ciphertext on its own
	// (no master key), so this seed is what exercises the no-leak contract.
	if ct, err := EncryptBytes(fuzzKey([]byte("seed")), bytes.Repeat([]byte{0xAB}, 70*1024)); err == nil && len(ct) > 100 {
		f.Add([]byte("seed"), ct[:len(ct)-100])
	}
	f.Add([]byte("seed"), []byte("not an age file"))
	f.Add([]byte("seed"), []byte("age-encryption.org/v1\n")) // header prefix, no body
	f.Add([]byte(""), []byte(""))
	f.Add([]byte(""), []byte{0})

	f.Fuzz(func(t *testing.T, keySeed, ciphertext []byte) {
		k := fuzzKey(keySeed)
		out, err := DecryptBytes(k, ciphertext)

		if err != nil {
			// Fail-closed: a blob that does not decrypt must surface as a Tamper
			// alarm (mustTamper asserts err != nil and cloakerr.KindOf == Tamper)
			// and must release no plaintext.
			mustTamper(t, err, "decrypt arbitrary bytes")
			if len(out) != 0 {
				t.Fatalf("decrypt of %d bytes failed (%v) but released %d plaintext bytes", len(ciphertext), err, len(out))
			}
			return
		}

		// Success is reachable only for genuine ciphertext: arbitrary bytes cannot
		// forge openable ciphertext without the master key (~2^-128). Decryption is
		// a pure function of (key, ciphertext), so a second decrypt must reproduce
		// the identical result and never flip to a failure. (Round-trip identity to
		// the original plaintext is FuzzRoundTrip's job; here only the ciphertext is
		// known, so determinism is the contract.)
		out2, err2 := DecryptBytes(k, ciphertext)
		if err2 != nil {
			t.Fatalf("decrypt succeeded then failed on the identical input: %v", err2)
		}
		if !bytes.Equal(out, out2) {
			t.Fatalf("decrypt not deterministic: first %d bytes, second %d bytes", len(out), len(out2))
		}
	})
}

// FuzzForeignAgeFileFailsClosed generalizes the fixed foreign-recipient unit
// tests (TestForeignAgeFileRejected scrypt, TestForeignX25519AgeFileRejected) to
// arbitrary attacker-chosen parameters. cloak's headline authenticity property
// is that possession of the master key is the ONLY way to produce ciphertext
// cloak will open: a syntactically perfect age file forged to a recipient the
// host fully controls -- but NOT a cloak/v1 stanza -- must fail closed as
// cloakerr.Tamper, release no forged plaintext, and never panic.
//
// This reaches tryUnwrapStanza's stanza-TYPE-mismatch reject branch (s.Type !=
// StanzaType) through age.Decrypt's full header parse over a WELL-FORMED foreign
// age file -- a path no existing fuzzer reaches by construction. FuzzDecryptArbitrary
// feeds shapeless bytes that essentially never form a valid age header (so its
// no-panic contract never actually traverses age's header parse to a clean
// stanza-type rejection), and FuzzCrossKeyFailsClosed uses a genuine cloak/v1
// stanza under the wrong master key (the AEAD-open-fails branch, a different
// reject). A scrypt recipient with a fuzzed passphrase is the cleanly-fuzzable
// foreign recipient: its stanza type is "scrypt", never "cloak/v1", so the file
// ALWAYS fails closed regardless of passphrase or forged plaintext -- no
// false-positive risk. The work factor is the minimum (2^1) because cloak rejects
// the stanza by TYPE without ever running scrypt, so the only cost is producing
// the forged file, kept cheap.
func FuzzForeignAgeFileFailsClosed(f *testing.F) {
	f.Add([]byte("master-seed"), "attacker-chosen-passphrase", []byte("a manifest the host forged"))
	f.Add([]byte(""), "p", []byte(""))
	// A multi-chunk forged payload straddling the 64 KiB age STREAM boundary, so
	// the foreign file carries a real multi-chunk payload, not just a header.
	f.Add([]byte("k"), "x", bytes.Repeat([]byte{0xAB}, 70*1024))

	f.Fuzz(func(t *testing.T, masterSeed []byte, passphrase string, forged []byte) {
		// age requires a non-empty scrypt passphrase; an empty one has nothing to
		// forge with (NewScryptRecipient errors), so skip it.
		if passphrase == "" {
			return
		}
		// Rejection happens at the header stanza-type check, so a huge multi-chunk
		// forgery only adds encryption cost without exercising new behavior; bound
		// the forged plaintext past the STREAM chunk boundary and move on.
		if len(forged) > 80*1024 {
			return
		}
		r, err := age.NewScryptRecipient(passphrase)
		if err != nil {
			return // age rejected the passphrase; nothing to forge
		}
		r.SetWorkFactor(1) // minimum: cloak never runs scrypt, keep forging cheap
		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, r)
		if err != nil {
			t.Fatalf("forging foreign age file failed: %v", err)
		}
		if _, err := w.Write(forged); err != nil {
			t.Fatalf("writing %d-byte forged plaintext failed: %v", len(forged), err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("closing forged age file failed: %v", err)
		}
		foreign := buf.Bytes()

		// cloak must refuse it: the stanza is scrypt, not cloak/v1. The decrypt
		// must fail closed as Tamper and release none of the forged bytes.
		master := fuzzKey(masterSeed)
		got, derr := DecryptBytes(master, foreign)
		mustTamper(t, derr, fmt.Sprintf("foreign scrypt age file (%d-byte forged plaintext)", len(forged)))
		if len(got) != 0 {
			t.Fatalf("foreign age file released %d bytes of forged plaintext", len(got))
		}
	})
}

// FuzzPackWriterContentAddress fuzzes the production pack-encryption path. Every
// pack pushed to the remote is encrypted through PackWriter (engine/push.go and
// cli seedcmd.go): plaintext written to it is streamed through the age STREAM
// encryptor into a temp file while the counting wrapper hashes and counts the
// ciphertext, yielding the pack id (hex SHA-256 of the ciphertext) and size the
// manifest records. The pack id doubles as the content-addressed integrity
// pointer the manifest stores, so PackWriter's contract is exact content
// addressing: after Close, ID must equal the SHA-256 of the bytes actually on
// disk, Size must equal that file's length, and the file must decrypt back to
// the exact plaintext written. The existing unit test pins this for one fixed
// payload split once; fuzzing generalizes it across arbitrary plaintext and
// write-chunking, exercising the counting/hashing accumulation under any number
// of partial writes. (FuzzStreamRoundTrip fuzzes Encrypt/Decrypt directly but
// never routes through PackWriter's temp-file, counting, and hashing layer.)
func FuzzPackWriterContentAddress(f *testing.F) {
	f.Add([]byte("key-seed"), []byte("packfile payload"), uint(7))
	f.Add([]byte(""), []byte(""), uint(1))
	// A payload straddling the age STREAM 64 KiB chunk boundary, fed in small
	// slices so the counting/hashing wrapper sees many partial writes.
	f.Add(bytes.Repeat([]byte{2}, keystore.KeySize), bytes.Repeat([]byte{0xCD}, 70*1024), uint(4096))

	f.Fuzz(func(t *testing.T, keySeed, plaintext []byte, writeChunk uint) {
		// This is the only fuzz target that touches the filesystem: each Write
		// chunk becomes a file write plus a hash update, so a large plaintext fed
		// one byte at a time would be hundreds of thousands of syscalls per exec
		// and stall the fuzzer. Bound the plaintext to comfortably past the 64 KiB
		// age STREAM chunk boundary (so multi-chunk reassembly is still exercised)
		// and let the fuzzer spend its budget on chunk-boundary variety instead.
		if len(plaintext) > 80*1024 {
			return
		}
		k := fuzzKey(keySeed)
		pw, err := NewPackWriter(t.TempDir(), k)
		if err != nil {
			t.Fatalf("NewPackWriter failed: %v", err)
		}
		// Stream the plaintext through in fuzz-sized slices; the +1 guards against
		// a zero-length step that would never advance the offset.
		chunk := int(writeChunk%65536) + 1
		for off := 0; off < len(plaintext); off += chunk {
			end := min(off+chunk, len(plaintext))
			if _, err := pw.Write(plaintext[off:end]); err != nil {
				t.Fatalf("Write failed: %v", err)
			}
		}
		if err := pw.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		ct, err := os.ReadFile(pw.Path())
		if err != nil {
			t.Fatalf("reading produced ciphertext file: %v", err)
		}
		// Size and ID must describe the bytes on disk exactly: the manifest stores
		// ID as the pack's integrity pointer and Size drives consolidation.
		if pw.Size() != int64(len(ct)) {
			t.Fatalf("Size = %d but the file holds %d bytes", pw.Size(), len(ct))
		}
		sum := sha256.Sum256(ct)
		if got := hex.EncodeToString(sum[:]); got != pw.ID() {
			t.Fatalf("ID = %s but sha256 of the file = %s", pw.ID(), got)
		}
		// The produced file must decrypt back to the exact plaintext under the same
		// key: the pack a push wrote is the pack a fetch can read.
		r, err := Decrypt(bytes.NewReader(ct), k)
		if err != nil {
			t.Fatalf("decrypt of produced pack failed: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("reading decrypted pack failed: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("decrypted pack mismatch: got %d bytes, want %d", len(got), len(plaintext))
		}
	})
}

// FuzzUnwrapStanzaList fuzzes identity.Unwrap's iteration over a LIST of
// stanzas, the boundary every other agecrypt test misses. cloak writes exactly
// one stanza, but age hands Unwrap whatever recipient stanzas the header
// carries, so a malformed or hostile age header can present many; Unwrap's
// contract is first-match-wins (return the file key of the FIRST stanza this
// identity can open) and exhaust-to-fail-closed (return age.ErrIncorrectIdentity
// with a nil key only when NO stanza opens). FuzzUnwrapStanza fuzzes the
// single-stanza tryUnwrapStanza in isolation, and FuzzStanzaWrapRoundTrip /
// FuzzCrossKeyFailsClosed only ever pass a one-element list, so the multi-stanza
// selection and exhaustion logic -- a bug in which would either return the
// wrong key or fail to open an openable blob -- had no coverage.
//
// The list is built from KNOWN-openable and KNOWN-unopenable stanzas so the
// expected result is derived by construction, not by re-running the parser
// (non-circular): a genuine Wrap under the master is openable and recovers its
// own file key; a corrupted stanza is unopenable two ways -- a flipped Type
// (rejected at tryUnwrapStanza's first check) or an emptied Body (rejected at
// the AEAD open, exercising the in-loop open-fails branch distinct from the
// early type reject). Each stanza's file key carries a distinct leading index
// byte, so "Unwrap returned the FIRST openable key" is a real check that would
// catch a return-a-later-stanza bug rather than just a count match.
func FuzzUnwrapStanzaList(f *testing.F) {
	f.Add([]byte("master"), []byte{0, 0}, []byte("fk")) // two openable: the first wins
	f.Add([]byte("master"), []byte{1, 0}, []byte("fk")) // first type-flipped: the second wins
	f.Add([]byte("master"), []byte{3, 0}, []byte("fk")) // first body-emptied: the second wins
	f.Add([]byte("master"), []byte{1, 3}, []byte("fk")) // both corrupt: fail closed
	f.Add([]byte("master"), []byte{}, []byte("fk"))     // empty list: fail closed
	f.Add([]byte(""), []byte{0}, []byte(""))            // single openable, empty file-key seed

	const maxStanzas = 16
	f.Fuzz(func(t *testing.T, masterSeed, kinds, fkSeed []byte) {
		master := fuzzKey(masterSeed)
		rcpt := recipient{master}
		id := identity{master}
		if len(kinds) > maxStanzas {
			kinds = kinds[:maxStanzas]
		}

		stanzas := make([]*age.Stanza, 0, len(kinds))
		firstOpenable := -1
		var expectedKey []byte
		for i, k := range kinds {
			// Distinct leading index byte so each openable stanza recovers a
			// distinct key; this is what makes "first openable wins" a real check.
			fk := append([]byte{byte(i)}, fkSeed...)
			ss, err := rcpt.Wrap(fk)
			if err != nil || len(ss) != 1 {
				t.Fatalf("Wrap(stanza %d) returned (len %d, err %v), want exactly one stanza", i, len(ss), err)
			}
			st := ss[0]
			switch {
			case k&1 == 0:
				// Genuine cloak stanza: openable under the master, recovers fk.
				if firstOpenable < 0 {
					firstOpenable = i
					expectedKey = fk
				}
			case k&2 == 0:
				// Flip the Type so tryUnwrapStanza rejects on its first check:
				// guaranteed unopenable regardless of salt/body/key.
				st.Type += "x"
			default:
				// Empty the AEAD body so the open fails (too short for the tag):
				// guaranteed unopenable, exercising the in-loop open-fails branch.
				st.Body = nil
			}
			stanzas = append(stanzas, st)
		}

		fileKey, err := id.Unwrap(stanzas)
		if firstOpenable < 0 {
			// No stanza opens (empty list or all corrupt): Unwrap must fail closed
			// with ErrIncorrectIdentity and never leak a key.
			if err == nil {
				t.Fatalf("Unwrap of an all-unopenable %d-stanza list returned a key, want ErrIncorrectIdentity", len(stanzas))
			}
			if !errors.Is(err, age.ErrIncorrectIdentity) {
				t.Fatalf("Unwrap of an all-unopenable list returned %v, want ErrIncorrectIdentity", err)
			}
			if fileKey != nil {
				t.Fatalf("fail-closed Unwrap returned a non-nil file key (%d bytes)", len(fileKey))
			}
			return
		}
		// At least one stanza opens: Unwrap must succeed and return the key of the
		// FIRST openable stanza in list order.
		if err != nil {
			t.Fatalf("Unwrap with an openable stanza at index %d failed: %v", firstOpenable, err)
		}
		if !bytes.Equal(fileKey, expectedKey) {
			t.Fatalf("Unwrap returned the wrong file key: got %x, want the first openable (index %d) key %x", fileKey, firstOpenable, expectedKey)
		}
	})
}
