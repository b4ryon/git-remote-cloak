// Unit test for the non-interactive bypass: when stdin is not a terminal
// (launchd, scripts, go test), Require must pass with a notice and never
// invoke the platform prompt.
package userpresence

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"golang.org/x/term"
)

func TestRequireNonInteractiveSkips(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal; skipping to avoid a user-presence prompt")
	}
	var buf bytes.Buffer
	if err := Require("unit test", &buf); err != nil {
		t.Fatalf("Require in a non-interactive session returned %v", err)
	}
	if !strings.Contains(buf.String(), "skipped") || !strings.Contains(buf.String(), "unit test") {
		t.Fatalf("notice = %q, want skip notice naming the operation", buf.String())
	}
}
