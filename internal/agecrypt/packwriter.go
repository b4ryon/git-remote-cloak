// PackWriter: streaming encryption of a packfile (or any blob) into a temp
// file while hashing the ciphertext, yielding the content-addressed pack id
// (SHA-256 of ciphertext) and size used by the manifest. Shared by the push
// path and the seed-remote debug command.
package agecrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"

	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// PackWriter encrypts plaintext written to it into a temp file. After
// Close, ID/Size/Path describe the finished ciphertext blob.
type PackWriter struct {
	w      io.WriteCloser
	f      *os.File
	hasher hash.Hash
	size   int64
	closed bool
}

// counting wraps the file to count ciphertext bytes.
type counting struct {
	pw *PackWriter
}

func (c counting) Write(p []byte) (int, error) {
	n, err := c.pw.f.Write(p)
	c.pw.hasher.Write(p[:n])
	c.pw.size += int64(n)
	return n, err
}

// NewPackWriter creates the temp file in dir and returns the encryptor.
func NewPackWriter(dir string, master keystore.Key) (*PackWriter, error) {
	f, err := os.CreateTemp(dir, "enc-*")
	if err != nil {
		return nil, err
	}
	pw := &PackWriter{f: f, hasher: sha256.New()}
	w, err := Encrypt(counting{pw}, master)
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	pw.w = w
	return pw, nil
}

// Write encrypts p.
func (p *PackWriter) Write(b []byte) (int, error) { return p.w.Write(b) }

// Close flushes the final STREAM chunk and closes the temp file.
func (p *PackWriter) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	if err := p.w.Close(); err != nil {
		p.f.Close()
		return err
	}
	return p.f.Close()
}

// Abort removes the temp file (call when the pack is not used).
func (p *PackWriter) Abort() {
	_ = p.Close()
	_ = os.Remove(p.f.Name())
}

// ID is the hex SHA-256 of the ciphertext (valid after Close).
func (p *PackWriter) ID() string { return hex.EncodeToString(p.hasher.Sum(nil)) }

// Size is the ciphertext size in bytes (valid after Close).
func (p *PackWriter) Size() int64 { return p.size }

// Path is the temp file holding the ciphertext.
func (p *PackWriter) Path() string { return p.f.Name() }
