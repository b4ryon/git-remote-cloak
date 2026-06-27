// End-to-end coverage for the pack-size guards: Tier 1b (cloak refuses an
// over-limit pack before upload, names the offending file, and leaves no
// half-upload) and Tier 1a (a host's own per-file rejection is surfaced as a
// clear TooLarge error). Both run the real helper through git against the
// hermetic harness host.
package integration

import (
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

// incompressible returns n bytes of high-entropy content (xorshift) so the
// packed/encrypted size tracks the byte count, instead of compressing away and
// dodging the size limit under test.
func incompressible(n int) string {
	b := make([]byte, n)
	x := uint32(2463534242)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return string(b)
}

func TestSizeLimitRefusesOversizedPush(t *testing.T) {
	host := harness.NewHost(t)
	a := harness.NewClient(t, "a", harness.NewKeyFile(t))
	a.InitRepo()
	a.MustGit("config", "cloak.maxPackBytes", "50000") // 50 KB ceiling
	a.WriteFile("big.bin", incompressible(200000))     // ~200 KB, incompressible
	a.WriteFile("small.txt", "tiny\n")
	a.Commit("c0")
	a.AddOrigin(host.Dir)

	out, stderr, err := a.Git("push", "-u", "origin", "main")
	if err == nil {
		t.Fatalf("oversized push should be refused; stdout=%s stderr=%s", out, stderr)
	}
	if !strings.Contains(stderr, "too large for host") {
		t.Fatalf("refusal not classified TooLarge: %s", stderr)
	}
	if !strings.Contains(stderr, "big.bin") {
		t.Fatalf("refusal did not name the offending file: %s", stderr)
	}
	// No half-upload: the host has no backend branch.
	if refs := host.Git("for-each-ref", "--format=%(refname)"); strings.Contains(refs, "refs/heads/cloak") {
		t.Fatalf("host gained a cloak branch from a refused push: %q", refs)
	}

	// Recovery: lifting the limit lets the same content push cleanly.
	a.MustGit("config", "cloak.maxPackBytes", "0")
	a.MustGit("push", "-u", "origin", "main")
	if refs := host.Git("for-each-ref", "--format=%(refname)"); !strings.Contains(refs, "refs/heads/cloak") {
		t.Fatalf("recovery push did not create the cloak branch: %q", refs)
	}
}

func TestHostFileLimitReportedClearly(t *testing.T) {
	host := harness.NewHost(t)
	// A host that rejects the push the way GitHub does for an oversized file.
	host.InstallPreReceive("#!/bin/sh\ncat >/dev/null\n" +
		"echo 'GH001: Large files detected.' >&2\n" +
		"echo 'File big.bin exceeds the file size limit of 100.00 MB' >&2\n" +
		"exit 1\n")

	a := harness.NewClient(t, "a", harness.NewKeyFile(t))
	a.InitRepo()
	a.MustGit("config", "cloak.maxPackBytes", "0") // disable pre-flight so the push reaches the host
	a.WriteFile("readme.md", "hi\n")
	a.Commit("c0")
	a.AddOrigin(host.Dir)

	out, stderr, err := a.Git("push", "-u", "origin", "main")
	if err == nil {
		t.Fatalf("push against a rejecting host should fail; stdout=%s stderr=%s", out, stderr)
	}
	if !strings.Contains(stderr, "too large for host") {
		t.Fatalf("host rejection not surfaced as TooLarge: %s", stderr)
	}
}
