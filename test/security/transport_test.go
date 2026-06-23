// End-to-end proof that cloak refuses git's arbitrary-command transports: a
// clone of a cloak::ext:: URL must fail without ever executing the embedded
// command.
package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestExtTransportCloneRejected(t *testing.T) {
	key := harness.NewKeyFile(t)
	c := harness.NewClient(t, "victim", key)
	sentinel := filepath.Join(c.Base, "pwned")

	// git clone cloak::ext::sh -c 'touch <sentinel>': the helper must reject
	// the ext:: backend URL before git's ext transport can run the command.
	_, stderr, err := c.Git("clone", "cloak::ext::sh -c 'touch "+sentinel+"'", c.Dir)
	if err == nil {
		t.Fatalf("clone of an ext:: backend URL succeeded\nstderr: %s", stderr)
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Fatalf("ext:: transport executed: sentinel %s was created", sentinel)
	}
	if !strings.Contains(stderr, "cloak:") {
		t.Fatalf("clone failed without a cloak diagnostic: %s", stderr)
	}
}
