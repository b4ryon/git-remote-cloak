// End-to-end coverage for the pack-size guards: Tier 1b (cloak refuses an
// over-limit pack before upload, names the offending file, and leaves no
// half-upload) and Tier 1a (a host's own per-file rejection is surfaced as a
// clear TooLarge error). Both run the real helper through git against the
// hermetic harness host.
package integration

import (
	"strconv"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

// incompressible returns n bytes of high-entropy content (xorshift) so the
// packed/encrypted size tracks the byte count, instead of compressing away and
// dodging the size limit under test.
func incompressible(n int) string { return incompressibleSeed(2463534242, n) }

// incompressibleSeed is incompressible with an explicit xorshift seed, so a
// caller can generate several DISTINCT high-entropy blobs that git will not
// delta-compress against each other (needed to force a multi-pack split).
func incompressibleSeed(seed uint32, n int) string {
	b := make([]byte, n)
	x := seed
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

// TestMultiPackPushRoundTrips proves an over-limit push is bin-packed into
// several sub-limit packs (instead of refused) and that a fresh clone applies
// every split pack independently and converges -- exercising the multi-pack push
// path and the unchanged multi-pack fetch path end-to-end.
func TestMultiPackPushRoundTrips(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	const limit = 2 << 20 // 2 MiB per-file cap
	a.MustGit("config", "cloak.maxPackBytes", strconv.Itoa(limit))
	// Four distinct ~1 MiB incompressible files: each fits under the limit, but
	// together they exceed it, so the push must split into several sub-limit
	// packs. Distinct seeds keep git from delta-compressing them into one pack.
	for i, name := range []string{"a.bin", "b.bin", "c.bin", "d.bin"} {
		a.WriteFile(name, incompressibleSeed(uint32(i+1)*2654435761, 1<<20))
	}
	a.Commit("c0")
	a.AddOrigin(host.Dir)
	a.MustGit("push", "-u", "origin", "main")

	sizes := hostPackSizes(t, host)
	if len(sizes) < 2 {
		t.Fatalf("oversized push was not split: got %d pack(s), want >= 2 (sizes %v)", len(sizes), sizes)
	}
	for _, s := range sizes {
		if s > limit {
			t.Fatalf("split produced an over-limit pack: %d > %d (all %v)", s, limit, sizes)
		}
	}

	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)
	if b.HeadOID() != a.HeadOID() {
		t.Fatalf("multi-pack clone HEAD %s != source %s", b.HeadOID(), a.HeadOID())
	}
}

// TestSingleOversizeFileStillRefused proves the residual case bin-packing cannot
// fix: a single file whose encrypted pack alone exceeds the limit is refused
// with the concise single-file message, names the offending file, and leaves no
// half-upload on the host.
func TestSingleOversizeFileStillRefused(t *testing.T) {
	host := harness.NewHost(t)
	a := harness.NewClient(t, "a", harness.NewKeyFile(t))
	a.InitRepo()
	const limit = 2 << 20
	a.MustGit("config", "cloak.maxPackBytes", strconv.Itoa(limit))
	a.WriteFile("huge.bin", incompressible(3<<20)) // 3 MiB: alone over the 2 MiB cap
	a.WriteFile("ok.txt", "small\n")
	a.Commit("c0")
	a.AddOrigin(host.Dir)

	out, stderr, err := a.Git("push", "-u", "origin", "main")
	if err == nil {
		t.Fatalf("a single over-limit file should be refused; stdout=%s stderr=%s", out, stderr)
	}
	if !strings.Contains(stderr, "push blocked") || !strings.Contains(stderr, "per-file limit") {
		t.Fatalf("refusal not the single-file message: %s", stderr)
	}
	if !strings.Contains(stderr, "huge.bin") {
		t.Fatalf("refusal did not name the offending file: %s", stderr)
	}
	// The message must be printed exactly once (the duplicate structured "fatal"
	// stderr line was removed; the full record now goes only to the debug log).
	if n := strings.Count(stderr, "push blocked - one file exceeds"); n != 1 {
		t.Fatalf("error printed %d times, want exactly 1 (de-dup): %s", n, stderr)
	}
	// Atomic: no half-upload, the host has no backend branch.
	if refs := host.Git("for-each-ref", "--format=%(refname)"); strings.Contains(refs, "refs/heads/cloak") {
		t.Fatalf("host gained a cloak branch from a refused push: %q", refs)
	}
}
