// Unit tests for PackWriter: ciphertext content addressing (ID/Size match
// the bytes on disk), decrypt round trip of the produced file, Abort
// cleanup, and double-Close safety.
package agecrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

func TestPackWriterRoundTrip(t *testing.T) {
	k := testKey(t)
	pt := make([]byte, 100*1024)
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}
	pw, err := NewPackWriter(t.TempDir(), k)
	if err != nil {
		t.Fatal(err)
	}
	// Split writes to exercise streaming.
	if _, err := pw.Write(pt[:30*1024]); err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write(pt[30*1024:]); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}

	ct, err := os.ReadFile(pw.Path())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ct)
	if got := hex.EncodeToString(sum[:]); got != pw.ID() {
		t.Fatalf("ID = %s, want sha256 of file %s", pw.ID(), got)
	}
	if pw.Size() != int64(len(ct)) {
		t.Fatalf("Size = %d, want file size %d", pw.Size(), len(ct))
	}
	r, err := Decrypt(bytes.NewReader(ct), k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("decrypted pack file does not match plaintext")
	}
}

func TestPackWriterAbortRemovesFile(t *testing.T) {
	pw, err := NewPackWriter(t.TempDir(), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	pw.Abort()
	if _, err := os.Stat(pw.Path()); !os.IsNotExist(err) {
		t.Fatalf("temp file still present after Abort: %v", err)
	}
}

func TestPackWriterDoubleClose(t *testing.T) {
	pw, err := NewPackWriter(t.TempDir(), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("second Close returned %v, want nil", err)
	}
}
