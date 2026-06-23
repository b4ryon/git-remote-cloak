// M0 scaffold integration tests: the compiled binary answers the
// capabilities exchange exactly as gitremote-helpers(7) requires, and the
// git-cloak entry point dispatches to the operator CLI.
package integration

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestScaffoldCapabilities(t *testing.T) {
	dir, err := harness.EnsureBuilt()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(dir, "git-remote-cloak"), "origin", "cloak::/dev/null")
	cmd.Stdin = strings.NewReader("capabilities\n\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper run: %v", err)
	}
	want := "fetch\npush\noption\n\n"
	if string(out) != want {
		t.Fatalf("capabilities output = %q, want %q", out, want)
	}
}

func TestScaffoldCloakHelp(t *testing.T) {
	dir, err := harness.EnsureBuilt()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(filepath.Join(dir, "git-cloak"), "--help").Output()
	if err != nil {
		t.Fatalf("git-cloak --help: %v", err)
	}
	if !strings.Contains(string(out), "git-cloak") {
		t.Fatalf("usage output missing tool name: %q", out)
	}
}
