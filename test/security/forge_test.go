// Forged- and swapped-blob rejection: a blob validly encrypted under a
// DIFFERENT key, and two legitimate pack blobs swapped on the host, must
// both be rejected before any object enters a client's object store. These
// prove the manifest (AEAD + pinned pack ids) is the single root of trust.
package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestForgedManifestRejected(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	a.WriteFile("f.md", "real content\n")
	a.Commit("c0")
	a.AddOrigin(host.Dir)
	a.MustGit("push", "-u", "origin", "main")

	// Forge a manifest-shaped blob encrypted under a different key.
	otherKey := harness.NewKeyFile(t)
	o := harness.NewClient(t, "o", otherKey)
	forged := encryptUnder(t, o, otherKey, `{"version":0,"generation":99,"refs":{},"packs":[]}`)
	forgedOID := host.HashObjectStdin(t, forged)
	host.ReplaceTreeEntry(t, "cloak", "manifest.age", forgedOID)

	victim := harness.NewClient(t, "victim", key)
	_, stderr, err := victim.Git("clone", "cloak::"+host.Dir, victim.Dir)
	if err == nil {
		t.Fatal("clone accepted a manifest forged under a foreign key")
	}
	if !strings.Contains(stderr, "TAMPER ALARM") {
		t.Fatalf("forged manifest not reported as tamper: %s", stderr)
	}
	// F1: the manifest is the first decrypt, so a key the victim cannot use
	// must steer them toward the key, not read purely as a host attack.
	if !strings.Contains(stderr, "cloak.keyRef") {
		t.Fatalf("wrong-key tamper gave no key hint: %s", stderr)
	}
	// F5: every fatal points at the per-repo debug log.
	if !strings.Contains(stderr, "see the debug log") {
		t.Fatalf("fatal did not point at the debug log: %s", stderr)
	}
}

func TestSwappedPackBlobsRejected(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	// Disable auto-consolidation so the two pushes stay two separate packs
	// to swap (otherwise the small second pack merges into the first).
	a.MustGit("config", "cloak.geometricFactor", "0")
	a.WriteFile("a.md", strings.Repeat("alpha ", 2000))
	a.Commit("c0")
	a.AddOrigin(host.Dir)
	a.MustGit("push", "-u", "origin", "main")
	a.WriteFile("b.md", strings.Repeat("beta ", 2000))
	a.Commit("c1")
	a.MustGit("push", "origin", "main")

	var packs []string
	for _, p := range host.LsTreeR("cloak") {
		if strings.HasPrefix(p, "packs/") {
			packs = append(packs, p)
		}
	}
	if len(packs) != 2 {
		t.Fatalf("want 2 packs to swap, have %d", len(packs))
	}
	// Swap the two pack blob contents: both are valid ciphertext under the
	// right key, but each now sits under the wrong manifest id.
	oid0 := strings.Fields(host.Git("ls-tree", "cloak", packs[0]))[2]
	oid1 := strings.Fields(host.Git("ls-tree", "cloak", packs[1]))[2]
	host.ReplaceTreeEntry(t, "cloak", packs[0], oid1)
	host.ReplaceTreeEntry(t, "cloak", packs[1], oid0)

	victim := harness.NewClient(t, "victim", key)
	_, stderr, err := victim.Git("clone", "cloak::"+host.Dir, victim.Dir)
	if err == nil {
		t.Fatal("clone accepted swapped pack blobs")
	}
	if !strings.Contains(stderr, "TAMPER ALARM") {
		t.Fatalf("swapped packs not reported as tamper: %s", stderr)
	}
	// F1 pack hint: the manifest decrypted, so the key is correct and a pack
	// failure points at the host, not the key.
	if !strings.Contains(stderr, "tampered pack data") {
		t.Fatalf("pack tamper gave no host-data hint: %s", stderr)
	}
	packDir := filepath.Join(victim.Dir, ".git", "objects", "pack")
	if entries, _ := os.ReadDir(packDir); len(entries) > 0 {
		t.Fatalf("objects indexed despite pack-id mismatch: %v", entries)
	}
}

// TestManifestRefWithoutObjectRejected exercises the integrity layer
// beneath AEAD: a manifest validly encrypted under the RIGHT key (so it
// decrypts and passes structural validation) that advertises a ref whose
// object no pack delivers. The fetch must fail closed once the helper's
// post-apply presence check finds the advertised object missing, even
// though every cryptographic check passed. This catches a manifest that
// promises history it cannot back, whether from corruption or a key
// holder's mistake.
func TestManifestRefWithoutObjectRejected(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	a.WriteFile("f.md", "real content\n")
	a.Commit("c0")
	a.AddOrigin(host.Dir)
	a.MustGit("push", "-u", "origin", "main")
	realOID := a.HeadOID()

	// Find the real pack id on the host (filename under packs/).
	var packID string
	for _, p := range host.LsTreeR("cloak") {
		if strings.HasPrefix(p, "packs/") {
			packID = strings.TrimSuffix(strings.TrimPrefix(p, "packs/"), ".age")
		}
	}
	if packID == "" {
		t.Fatal("no pack found on host")
	}

	// A manifest under the right key: keeps main resolvable but adds a
	// ghost branch pointing at an object no pack contains.
	ghost := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	doctored := `{"version":1,"repo_id":"0123456789abcdef0123456789abcdef","generation":1,"head":"refs/heads/main","refs":{` +
		`"refs/heads/main":"` + realOID + `",` +
		`"refs/heads/ghost":"` + ghost + `"},` +
		`"packs":[{"id":"` + packID + `","size":1}]}`
	blob := encryptUnder(t, a, key, doctored)
	oid := host.HashObjectStdin(t, blob)
	host.ReplaceTreeEntry(t, "cloak", "manifest.age", oid)

	victim := harness.NewClient(t, "victim", key)
	_, stderr, err := victim.Git("clone", "cloak::"+host.Dir, victim.Dir)
	if err == nil {
		t.Fatal("clone accepted a manifest advertising an unbacked ref")
	}
	if !strings.Contains(stderr, "TAMPER ALARM") {
		t.Fatalf("unbacked ref not reported as tamper: %s", stderr)
	}
}

// encryptUnder encrypts plaintext with the given client's debug encrypt.
func encryptUnder(t *testing.T, c *harness.Client, keyFile, plaintext string) []byte {
	t.Helper()
	out, errb, err := c.CloakStdinBytes(plaintext, "debug", "encrypt", "--key", "file:"+keyFile)
	if err != nil {
		t.Fatalf("debug encrypt: %v\n%s", err, errb)
	}
	return out
}
