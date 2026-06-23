// Unit tests for protocol-stream validation that fails before any session
// or remote work: malformed lines inside a fetch batch.
package helper

import (
	"bytes"
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
