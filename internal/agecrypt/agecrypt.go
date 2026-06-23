// Package agecrypt implements cloak's encryption: the age v1 file format
// (header MAC + 64 KiB chunked ChaCha20-Poly1305 STREAM payload) with a
// custom symmetric stanza. Each blob gets a fresh random age file key; the
// stanza wraps that file key with ChaCha20-Poly1305 under a per-blob key AND
// nonce, both read from a single HKDF-SHA-256 stream keyed by the shared
// master key with a random per-blob salt (domain label "cloak/v1 wrap").
// The nonce is derived, not stored: a fresh 256-bit CSPRNG salt per blob makes
// the wrap (key, nonce) pair fresh with overwhelming probability. Safety rests
// entirely on that salt width -- a salt collision would reproduce the SAME
// (key, nonce) over two distinct file keys (catastrophic reuse, not a benign
// failure), so the salt must stay full-width and from crypto/rand. Possession
// of the master key is the only way to produce or open
// valid ciphertext, which is what gives cloak its authenticity property.
package agecrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// StanzaType identifies cloak's key-wrapping stanza in age headers.
const StanzaType = "cloak/v1"

const (
	saltSize  = 32
	wrapLabel = "cloak/v1 wrap"
)

// deriveWrapKey derives the per-blob file-key-wrapping key AND nonce from the
// master key and the stanza salt, reading both from one HKDF stream. Both are
// deterministic in (master, salt), so a fresh per-blob salt yields a fresh
// (key, nonce) pair. The 256-bit crypto/rand salt (saltSize) is what prevents
// nonce reuse: two blobs colliding on salt would reuse one (key, nonce) over
// different file keys -- catastrophic for ChaCha20-Poly1305, negligible at 32
// random bytes, and the reason the salt must never be shortened or made
// predictable.
func deriveWrapKey(master keystore.Key, salt []byte) (wk, nonce []byte, err error) {
	r := hkdf.New(sha256.New, master.Bytes(), salt, []byte(wrapLabel))
	out := make([]byte, chacha20poly1305.KeySize+chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, nil, err
	}
	return out[:chacha20poly1305.KeySize], out[chacha20poly1305.KeySize:], nil
}

// zero best-effort wipes ephemeral key material (see keystore.Key.Wipe for
// the Go limitation: this is defense in depth, not a guarantee).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// recipient implements age.Recipient with the cloak symmetric stanza.
type recipient struct{ master keystore.Key }

func (r recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	wk, nonce, err := deriveWrapKey(r.master, salt)
	if err != nil {
		return nil, err
	}
	defer zero(wk)
	aead, err := chacha20poly1305.New(wk)
	if err != nil {
		return nil, err
	}
	return []*age.Stanza{{
		Type: StanzaType,
		Args: []string{base64.RawStdEncoding.EncodeToString(salt)},
		Body: aead.Seal(nil, nonce, fileKey, nil),
	}}, nil
}

// identity implements age.Identity for the cloak symmetric stanza.
type identity struct{ master keystore.Key }

func (i identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type != StanzaType || len(s.Args) != 1 {
			continue
		}
		salt, err := base64.RawStdEncoding.DecodeString(s.Args[0])
		if err != nil || len(salt) != saltSize {
			continue
		}
		wk, nonce, err := deriveWrapKey(i.master, salt)
		if err != nil {
			continue
		}
		aead, err := chacha20poly1305.New(wk)
		if err != nil {
			zero(wk)
			continue
		}
		fileKey, err := aead.Open(nil, nonce, s.Body, nil)
		zero(wk)
		if err != nil {
			// Wrong master key and a tampered stanza are
			// indistinguishable here; both end as ErrIncorrectIdentity.
			continue
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

// tamper wraps any decrypt-path failure: at the AEAD level a wrong key and
// modified ciphertext cannot be told apart.
func tamper(op string, err error) error {
	return cloakerr.New(cloakerr.Tamper, op+" (wrong key or modified ciphertext)", err)
}

// Encrypt returns a WriteCloser encrypting to dst under the master key.
// Close must be called to flush the final STREAM chunk.
func Encrypt(dst io.Writer, master keystore.Key) (io.WriteCloser, error) {
	w, err := age.Encrypt(dst, recipient{master})
	if err != nil {
		return nil, cloakerr.New(cloakerr.Crypto, "encrypt", err)
	}
	return w, nil
}

// Decrypt returns a Reader of the plaintext of the age file read from src.
// Header failures surface here as Tamper; payload chunk failures surface as
// errors from Read and must also be treated as Tamper by callers (the
// tamperReader below does that mapping).
func Decrypt(src io.Reader, master keystore.Key) (io.Reader, error) {
	r, err := age.Decrypt(src, identity{master})
	if err != nil {
		return nil, tamper("decrypt header", err)
	}
	return tamperReader{r}, nil
}

// tamperReader maps payload read errors to the Tamper classification.
type tamperReader struct{ r io.Reader }

func (t tamperReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF {
		return n, tamper("decrypt payload", err)
	}
	return n, err
}

// EncryptBytes encrypts a small in-memory blob (e.g. the manifest).
func EncryptBytes(master keystore.Key, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := Encrypt(&buf, master)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, cloakerr.New(cloakerr.Crypto, "encrypt", err)
	}
	if err := w.Close(); err != nil {
		return nil, cloakerr.New(cloakerr.Crypto, "encrypt", err)
	}
	return buf.Bytes(), nil
}

// DecryptBytes decrypts a small in-memory blob.
func DecryptBytes(master keystore.Key, ciphertext []byte) ([]byte, error) {
	r, err := Decrypt(bytes.NewReader(ciphertext), master)
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, err // already Tamper-classified by tamperReader
	}
	return out, nil
}
