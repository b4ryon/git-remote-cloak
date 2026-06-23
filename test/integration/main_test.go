// TestMain for the integration suite: enforces the ~/tmp temp-file
// convention and builds the helper binary once for all scenario tests.
package integration

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
