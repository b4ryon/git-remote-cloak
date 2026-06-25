// Streaming and API-shape tests for the cloak Encrypt/Decrypt wrappers:
// Close() is mandatory, interleaved small writes and io.Copy match a single
// write, the decrypt reader tolerates short reads and obeys the io.Reader
// contract (clean single EOF), extra chunk-boundary sizes round-trip, and a
// large synthetic stream round-trips with bounded memory.
package agecrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
	"testing/iotest"
)

func TestWriteWithoutCloseProducesInvalidFile(t *testing.T) {
	k := testKey(t)
	var buf bytes.Buffer
	w, err := Encrypt(&buf, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("data that never gets its final chunk flushed")); err != nil {
		t.Fatal(err)
	}
	// Deliberately skip w.Close(): the final STREAM chunk is never written.
	if _, err := DecryptBytes(k, buf.Bytes()); err == nil {
		t.Fatal("ciphertext written without Close() decrypted successfully (footgun)")
	}
}

func TestStreamingEquivalence(t *testing.T) {
	k := testKey(t)
	pt := make([]byte, 3*64*1024+123) // multiple chunks, non-aligned tail
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}

	enc := func(write func(w io.Writer) error) []byte {
		var buf bytes.Buffer
		w, err := Encrypt(&buf, k)
		if err != nil {
			t.Fatal(err)
		}
		if err := write(w); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	cts := map[string][]byte{
		"single": enc(func(w io.Writer) error { _, err := w.Write(pt); return err }),
		"copy":   enc(func(w io.Writer) error { _, err := io.Copy(w, bytes.NewReader(pt)); return err }),
		"small": enc(func(w io.Writer) error {
			for off := 0; off < len(pt); off += 7919 { // odd prime stride crosses chunk boundaries
				end := off + 7919
				if end > len(pt) {
					end = len(pt)
				}
				if _, err := w.Write(pt[off:end]); err != nil {
					return err
				}
			}
			return nil
		}),
	}
	for name, ct := range cts {
		got, err := DecryptBytes(k, ct)
		if err != nil {
			t.Fatalf("%s: decrypt: %v", name, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("%s: round-trip mismatch", name)
		}
	}
}

func TestDecryptPartialReaders(t *testing.T) {
	k := testKey(t)
	pt := make([]byte, 64*1024+777) // spans a chunk boundary
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}
	ct, err := EncryptBytes(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	wrappers := map[string]func(io.Reader) io.Reader{
		"one-byte": iotest.OneByteReader,
		"half":     iotest.HalfReader,
	}
	for name, wrap := range wrappers {
		dr, err := Decrypt(wrap(bytes.NewReader(ct)), k)
		if err != nil {
			t.Fatalf("%s: decrypt init: %v", name, err)
		}
		got, err := io.ReadAll(dr)
		if err != nil {
			t.Fatalf("%s: read: %v", name, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("%s: round-trip mismatch", name)
		}
	}
}

func TestDecryptReaderContract(t *testing.T) {
	k := testKey(t)
	pt := make([]byte, 50000)
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}
	ct, err := EncryptBytes(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	dr, err := Decrypt(bytes.NewReader(ct), k)
	if err != nil {
		t.Fatal(err)
	}
	// iotest.TestReader reads in many sizes and verifies a clean single EOF,
	// catching any tamperReader regression that mangles the io.Reader contract.
	if err := iotest.TestReader(dr, pt); err != nil {
		t.Fatalf("decrypt reader violates io.Reader contract: %v", err)
	}
}

func TestRoundTripBoundarySweep(t *testing.T) {
	k := testKey(t)
	const chunk = 64 * 1024
	// Exact multiples and +-1 around the 2nd/3rd chunk boundary (complements
	// the {0,1,63,64K,64K+1,1M} set in agecrypt_test.go).
	for _, n := range []int{chunk - 1, 2 * chunk, 2*chunk + 1, 3 * chunk} {
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
			t.Fatalf("size %d: round-trip mismatch", n)
		}
	}
}

// countReader yields n deterministic bytes without allocating them, so a
// multi-hundred-MB stream can flow through the codec with O(1) memory.
type countReader struct {
	remaining int64
	next      byte
}

func (c *countReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > c.remaining {
		n = int(c.remaining)
	}
	for j := 0; j < n; j++ {
		p[j] = c.next
		c.next++
	}
	c.remaining -= int64(n)
	return n, nil
}

func hashOfCountStream(total int64) []byte {
	h := sha256.New()
	_, _ = io.Copy(h, &countReader{remaining: total})
	return h.Sum(nil)
}

func TestLargeStreamConstantMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-hundred-MB streaming round-trip in -short mode")
	}
	k := testKey(t)
	const total = 512 << 20 // 512 MiB => thousands of 64 KiB chunks
	want := hashOfCountStream(total)

	pr, pw := io.Pipe()
	go func() {
		w, err := Encrypt(pw, k)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(w, &countReader{remaining: total}); err != nil {
			pw.CloseWithError(err)
			return
		}
		if err := w.Close(); err != nil {
			pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()

	dr, err := Decrypt(pr, k)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, dr); err != nil {
		t.Fatalf("streaming decrypt: %v", err)
	}
	if !bytes.Equal(h.Sum(nil), want) {
		t.Fatal("large-stream round-trip hash mismatch")
	}
}
