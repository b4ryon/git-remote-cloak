// Unit tests for the git-cloak CLI dispatch (M0: usage and unknown-command).
package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelp(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Main([]string{"--help"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("--help exit code = %d", code)
	}
	if !strings.Contains(out.String(), "git-cloak") {
		t.Fatalf("usage output missing tool name: %q", out.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Main([]string{"frobnicate"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("unknown command exit code = %d, want 2", code)
	}
}
