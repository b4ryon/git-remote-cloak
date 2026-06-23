// Unit tests for state directory naming: "." and ".." must never be used
// as directory names (they would escape the cloak/ directory), falling
// back to the URL hash like any other unsafe name.
package state

import (
	"strings"
	"testing"
)

func TestDirNameRejectsDotNames(t *testing.T) {
	for _, name := range []string{".", ".."} {
		got := DirName(name, "ssh://host/repo")
		if got == name {
			t.Fatalf("DirName(%q) used the name verbatim", name)
		}
		if !strings.HasPrefix(got, "url-") {
			t.Fatalf("DirName(%q) = %q, want url-hash fallback", name, got)
		}
	}
	// "..." has no path meaning and stays a valid literal name.
	if got := DirName("...", "u"); got != "..." {
		t.Fatalf("DirName(\"...\") = %q, want verbatim", got)
	}
}
