// Pins the never-plain-force invariant at the source: the only two backend
// push command lines that can be constructed are plain fast-forward and
// force-with-lease with an explicit expected value.
package backend

import (
	"strings"
	"testing"
)

func TestPushArgsNeverPlainForce(t *testing.T) {
	for _, lease := range []string{"", "0123456789abcdef0123456789abcdef01234567"} {
		args := pushArgs("cloak", "deadbeef", lease)
		for _, a := range args {
			if a == "--force" || a == "-f" {
				t.Fatalf("plain force in backend push argv: %v", args)
			}
		}
		joined := strings.Join(args, " ")
		if lease == "" {
			if strings.Contains(joined, "force") {
				t.Fatalf("fast-forward push contains force flag: %v", args)
			}
		} else {
			if !strings.Contains(joined, "--force-with-lease=refs/heads/cloak:"+lease) {
				t.Fatalf("lease push missing explicit expected value: %v", args)
			}
		}
	}
}
