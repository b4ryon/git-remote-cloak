// Scenario 0 (DESIGN.md testing plan), clone half for M2: a seeded remote
// clones back byte-identical with full history, and the host stores only
// opaque encrypted blobs with deterministic commit metadata. The push half
// completes in M3.
package integration

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

var hostPathRe = regexp.MustCompile(`^(manifest\.age|packs/[0-9a-f]{64}\.age)$`)

func TestScenario0CloneHalf(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)

	src := harness.NewClient(t, "src", key)
	src.InitRepo()
	src.WriteFile("notes/alpha.md", "# Alpha\nplaintext sentinel A\n")
	src.Commit("first commit")
	src.WriteFile("beta.md", "beta content\n")
	src.Commit("second commit")
	src.MustGit("tag", "-a", "v1", "-m", "release tag")
	src.MustGit("branch", "feature")

	src.MustCloak("debug", "seed-remote", "--key", "file:"+key, "--from", src.Dir, host.Dir)

	dst := harness.NewClient(t, "dst", key)
	dst.MustClone(host.Dir)

	if got, want := dst.HeadOID(), src.HeadOID(); got != want {
		t.Fatalf("HEAD mismatch: clone %s, source %s", got, want)
	}
	if got, want := dst.MustGit("rev-list", "--count", "HEAD"), src.MustGit("rev-list", "--count", "HEAD"); got != want {
		t.Fatalf("history length mismatch: clone %s, source %s", got, want)
	}
	if got, want := dst.MustGit("rev-parse", "v1"), src.MustGit("rev-parse", "v1"); got != want {
		t.Fatalf("tag v1 mismatch: clone %s, source %s", got, want)
	}
	if got, want := dst.MustGit("rev-parse", "origin/feature"), src.MustGit("rev-parse", "feature"); got != want {
		t.Fatalf("branch feature mismatch: clone %s, source %s", got, want)
	}
	for _, rel := range []string{"notes/alpha.md", "beta.md"} {
		a, err := os.ReadFile(filepath.Join(src.Dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dst.Dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("file %s differs between source and clone", rel)
		}
	}

	for _, path := range host.LsTreeR("cloak") {
		if !hostPathRe.MatchString(path) {
			t.Fatalf("host tree leaks a non-opaque path: %q", path)
		}
	}
	meta := host.Git("log", "--format=%an|%ae|%cn|%ce|%s", "cloak")
	for _, line := range strings.Split(meta, "\n") {
		if line != "cloak|cloak@cloak|cloak|cloak@cloak|cloak" {
			t.Fatalf("backend commit metadata not deterministic: %q", line)
		}
	}
}
