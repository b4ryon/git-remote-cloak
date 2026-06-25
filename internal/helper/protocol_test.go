// Unit tests for protocol-stream validation that fails before any session
// or remote work: malformed lines inside a fetch batch, and a read error that
// truncates a batch mid-stream.
package helper

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestFetchBatchRejectsForeignLine(t *testing.T) {
	var out, errb bytes.Buffer
	in := "fetch aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main\nWAT\n"
	code := Main([]string{"origin", "cloak::/dev/null"}, strings.NewReader(in), &out, &errb)
	if code == 0 {
		t.Fatal("foreign line inside a fetch batch did not fail")
	}
	if !strings.Contains(errb.String(), "protocol") {
		t.Fatalf("stderr = %q, want a protocol error", errb.String())
	}
}

// erringReader yields its data once, then fails every subsequent Read with err.
// It drives bufio.Scanner cleanly past the opening batch line and into a read
// failure on the next Scan() - the truncated-batch shape a >1 MiB line or a
// broken stdin pipe produces, which collectBatch must refuse rather than treat
// as a clean end-of-batch.
type erringReader struct {
	data []byte
	err  error
}

func (r *erringReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

// TestCollectBatchSurfacesReadError pins that collectBatch consults Scanner.Err()
// after its loop: a mid-batch read failure (Scan()==false with Err()!=nil) must
// be surfaced, not swallowed as a clean end-of-batch. collectBatch runs before
// ensure()/fetchBatch/pushBatch, so surfacing here is what keeps a truncated
// push batch from being partially executed and reported "ok".
func TestCollectBatchSurfacesReadError(t *testing.T) {
	sentinel := errors.New("stdin pipe broke")
	sc := bufio.NewScanner(&erringReader{data: []byte("fetch aaaa refs/heads/main\n"), err: sentinel})
	if !sc.Scan() {
		t.Fatalf("first Scan failed to read the opening line: %v", sc.Err())
	}
	items, err := collectBatch(sc, sc.Text(), "fetch ")
	if err == nil {
		t.Fatalf("collectBatch swallowed a mid-batch read error; items=%q, err=nil", items)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("collectBatch error does not unwrap to the read failure: %v", err)
	}
	if !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("collectBatch error lacks protocol context: %v", err)
	}
}
