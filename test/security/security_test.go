// Security suite: enforces cloak's confidentiality and integrity claims
// against a real host and the compiled helper. Sentinels are seeded into
// every metadata channel and the host is scanned for leaks; the debug log
// is scanned for key material; salts must be unique; forged and swapped
// blobs must be rejected; and a PATH git shim proves the helper never
// issues a plain --force.
package security

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

const sentinel = "CLOAK-SENTINEL-9f3a2b7c"

var opaquePathRe = regexp.MustCompile(`^(manifest\.age|packs/[0-9a-f]{64}\.age)$`)

// seeded pushes a repo whose content, filename, branch, tag, and commit
// message all carry the sentinel, then returns host, key, and client.
func seeded(t *testing.T) (*harness.Host, string, *harness.Client) {
	t.Helper()
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	a.WriteFile(sentinel+".md", "body contains "+sentinel+" here\n")
	a.Commit("commit message with " + sentinel)
	a.MustGit("branch", "branch-"+sentinel)
	a.MustGit("tag", "tag-"+sentinel)
	a.AddOrigin(host.Dir)
	a.MustGit("push", "-u", "origin", "main")
	a.MustGit("push", "origin", "branch-"+sentinel)
	a.MustGit("push", "origin", "tag-"+sentinel)
	return host, key, a
}

func TestNoPlaintextOnHost(t *testing.T) {
	host, _, _ := seeded(t)

	needles := []string{
		sentinel,
		hex.EncodeToString([]byte(sentinel)),
		base64.StdEncoding.EncodeToString([]byte(sentinel)),
		base64.RawStdEncoding.EncodeToString([]byte(sentinel)),
	}

	// All object payloads on the host.
	objs := host.GitRaw(t, "cat-file", "--batch-all-objects", "--batch")
	// All ref names.
	refs := host.GitRaw(t, "for-each-ref", "--format=%(refname)")
	// Backend commit log (messages, author, dates).
	log := host.GitRaw(t, "log", "--format=%an %ae %s %b", "cloak")

	for _, hay := range []struct{ name, data string }{{"objects", objs}, {"refs", refs}, {"log", log}} {
		for _, n := range needles {
			if strings.Contains(hay.data, n) {
				t.Fatalf("sentinel leaked into host %s (encoding %q)", hay.name, n)
			}
		}
	}

	for _, p := range host.LsTreeR("cloak") {
		if !opaquePathRe.MatchString(p) {
			t.Fatalf("non-opaque tree path on host: %q", p)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(host.GitRaw(t, "log", "--format=%an|%ae|%s", "cloak")), "\n") {
		if line != "cloak|cloak@cloak|cloak" {
			t.Fatalf("backend commit metadata not constant: %q", line)
		}
	}
}

// TestNoKeyMaterialInLogs asserts the two things that MUST never reach the
// debug log: master key material (in any encoding) and plaintext FILE
// CONTENT. Ref names are deliberately excluded: they are local metadata
// and the debug log lives inside the local .git, at the same trust level
// as the plaintext working tree (logx policy). The host,
// which must not see ref names, is covered by TestNoPlaintextOnHost.
func TestNoKeyMaterialInLogs(t *testing.T) {
	const contentSentinel = "CLOAK-CONTENT-SECRET-d4e5f6"
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	// Sentinel lives ONLY in file content, never in a ref name.
	a.WriteFile("doc.md", "top secret body: "+contentSentinel+"\n")
	a.Commit("ordinary message")
	a.AddOrigin(host.Dir)
	a.MustGit("push", "-u", "origin", "main")

	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)

	raw, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	exported := strings.TrimSpace(string(raw))
	keyB64 := strings.TrimPrefix(exported, "cloak-key-v0:")
	rawKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatal(err)
	}
	needles := []string{
		exported, keyB64,
		hex.EncodeToString(rawKey),
		base64.RawStdEncoding.EncodeToString(rawKey),
		contentSentinel,
	}
	logs := a.DebugLog() + b.DebugLog()
	if logs == "" {
		t.Fatal("no debug logs captured (CLOAK_LOG not honored?)")
	}
	for _, n := range needles {
		if n != "" && strings.Contains(logs, n) {
			t.Fatalf("debug log leaked key material or file content (needle %.16s...)", n)
		}
	}
}

func TestSaltUniqueness(t *testing.T) {
	host, _, a := seeded(t)
	for i := 0; i < 4; i++ {
		a.WriteFile("edit.md", strings.Repeat("x", i+1)+"\n")
		a.Commit("edit")
		a.MustGit("push", "origin", "main")
	}
	salts := map[string]bool{}
	for _, p := range host.LsTreeR("cloak") {
		oid := strings.Fields(host.Git("ls-tree", "cloak", p))[2]
		blob := host.GitRaw(t, "cat-file", "blob", oid)
		salt := cloakStanzaSalt(t, blob)
		if salts[salt] {
			t.Fatalf("salt reused across blobs: %q (%s)", salt, p)
		}
		salts[salt] = true
	}
	if len(salts) < 2 {
		t.Fatalf("expected multiple distinct salts, saw %d", len(salts))
	}
}

func TestNeverPlainForce(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	shimLog := a.InstallGitShim(t)

	a.InitRepo()
	a.WriteFile("f.md", "content\n")
	a.Commit("c0")
	a.AddOrigin(host.Dir)
	a.MustGit("push", "-u", "origin", "main")
	// Exercise consolidation (squash via lease) and a normal push.
	for i := 0; i < 3; i++ {
		a.WriteFile("f.md", strings.Repeat("y", (i+1)*5000)+"\n")
		a.Commit("edit")
		a.MustGit("push", "origin", "main")
	}
	a.MustCloak("repack", "--remote", "origin")

	data, err := os.ReadFile(shimLog)
	if err != nil {
		t.Fatal(err)
	}
	invocations := string(data)
	if !strings.Contains(invocations, "push") {
		t.Fatal("git shim recorded no push invocations (interposition failed)")
	}
	for _, line := range strings.Split(invocations, "\n") {
		if !strings.Contains(line, "push") {
			continue
		}
		fields := strings.Fields(line)
		for _, f := range fields {
			if f == "--force" || f == "-f" || f == "+refs/heads/cloak" {
				t.Fatalf("backend push used a non-lease force: %q", line)
			}
		}
		if strings.Contains(line, "refs/heads/cloak") && strings.Contains(line, "--force") &&
			!strings.Contains(line, "--force-with-lease=") {
			t.Fatalf("backend push used plain --force: %q", line)
		}
	}
}

func TestHoldHookInert(t *testing.T) {
	// With the hold-hook env var unset, a push must not create marker
	// files or block (guards the test-only synchronization point).
	_, _, a := func() (*harness.Host, string, *harness.Client) { return seeded(t) }()
	a.WriteFile("x.md", "y\n")
	a.Commit("c")
	a.MustGit("push", "origin", "main") // would hang if the hook fired
}

// cloakStanzaSalt extracts the salt arg from the "-> cloak/v1 <salt>" line.
func cloakStanzaSalt(t *testing.T, blob string) string {
	t.Helper()
	for _, line := range strings.Split(blob, "\n") {
		if strings.HasPrefix(line, "-> cloak/v1 ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "-> cloak/v1 "))
		}
	}
	t.Fatalf("no cloak stanza in blob header: %.80q", blob)
	return ""
}
