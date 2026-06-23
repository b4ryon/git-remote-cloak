// TestMain for the security suite: enforces the ~/tmp temp-file convention
// and builds the helper binary once. The suite itself (plaintext-leak
// scanner, key-in-logs scanner, salt uniqueness, forged-blob rejection,
// never-plain-force shim) lands in milestone 5.
package security

import (
	"fmt"
	"os"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestMain(m *testing.M) {
	if err := harness.RequireTmpHome(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := harness.EnsureBuilt(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
