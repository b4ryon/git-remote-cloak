// M5 scenarios from the DESIGN.md testing plan: 4 (rollback injection ->
// alarm -> accept-rollback recovery), 5 (ciphertext corruption of a pack
// and the manifest reported as tamper and never applied), and 8 (recovery
// of a clone from remote ciphertext plus only the exported key).
package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestScenario4RollbackInjection(t *testing.T) {
	host, key, a := pushSetup(t)
	old := host.Git("rev-parse", "cloak")

	a.WriteFile("more.md", "second push\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")

	// B clones at generation 2, pinning it.
	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)

	// Host rolls the backend branch back to generation 1.
	host.Git("update-ref", "refs/heads/cloak", old)

	_, stderr, err := b.Git("fetch", "origin")
	if err == nil {
		t.Fatal("fetch accepted a rolled-back remote")
	}
	if !strings.Contains(stderr, "ROLLBACK ALARM") {
		t.Fatalf("rollback not reported as an alarm: %s", stderr)
	}

	// accept-rollback (non-interactive: presence check is skipped) clears
	// the pin; the next fetch then succeeds at the lower generation.
	out, errb, err := b.Cloak("accept-rollback", "--remote", "origin")
	if err != nil {
		t.Fatalf("accept-rollback failed: %v\n%s", err, errb)
	}
	if !strings.Contains(out, "Accepted") {
		t.Fatalf("accept-rollback output: %q", out)
	}
	if _, _, err := b.Git("fetch", "origin"); err != nil {
		t.Fatalf("fetch still failing after accept-rollback: %v", err)
	}
}

// A corrupt local rollback pin must never be silently swallowed. Fetch fails
// closed (CheckPin surfaces "corrupt pin file" rather than downgrading to
// trust-on-first-use), and accept-rollback -- the recovery command for exactly
// this situation -- reports the unreadable pin instead of "nothing to accept"
// while still clearing it so the next fetch recovers.
func TestCorruptPinSurfacedAndRecoverable(t *testing.T) {
	host, key, a := pushSetup(t)
	a.WriteFile("more.md", "second push\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")

	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)

	corruptStatePins(t, b)

	// Fail-closed: a corrupt pin must not read as "no pin".
	if _, stderr, err := b.Git("fetch", "origin"); err == nil {
		t.Fatalf("fetch accepted a corrupt pin (should fail closed): %s", stderr)
	} else if !strings.Contains(stderr, "corrupt pin") {
		t.Fatalf("corrupt pin not surfaced on fetch: %s", stderr)
	}

	out, errb, err := b.Cloak("accept-rollback", "--remote", "origin")
	if err != nil {
		t.Fatalf("accept-rollback failed: %v\n%s", err, errb)
	}
	if strings.Contains(out, "nothing to accept") {
		t.Fatalf("accept-rollback silently swallowed the corrupt pin: %q", out)
	}
	if !strings.Contains(out, "Accepted") {
		t.Fatalf("accept-rollback did not re-pin: %q", out)
	}
	if _, _, err := b.Git("fetch", "origin"); err != nil {
		t.Fatalf("fetch still failing after accept-rollback: %v", err)
	}
}

// corruptStatePins overwrites every rollback pin file in the client's per-remote
// state directories with unparseable content.
func corruptStatePins(t *testing.T, c *harness.Client) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(c.Dir, ".git", "cloak", "*", "generation"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no rollback pin file found to corrupt")
	}
	for _, m := range matches {
		if err := os.WriteFile(m, []byte("garbage no numbers\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScenario5CorruptionInjection(t *testing.T) {
	flip := func(b []byte) []byte {
		out := append([]byte(nil), b...)
		out[len(out)/2] ^= 0x01
		return out
	}
	t.Run("pack", func(t *testing.T) {
		host, key, _ := pushSetup(t)
		corruptHostBlob(t, host, "packs/", flip)
		assertCloneTamperNoObjects(t, host, key)
	})
	t.Run("manifest", func(t *testing.T) {
		host, key, _ := pushSetup(t)
		corruptHostBlob(t, host, "manifest.age", flip)
		assertCloneTamperNoObjects(t, host, key)
	})
}

func TestScenario8RecoveryFromCiphertextAndKey(t *testing.T) {
	host, key, a := pushSetup(t)
	a.WriteFile("notes/keep.md", "important content\n")
	a.Commit("c1")
	a.MustGit("tag", "v1")
	a.MustGit("push", "origin", "main")
	a.MustGit("push", "origin", "v1")
	want := a.HeadOID()

	// Simulate disaster recovery: a brand new machine with ONLY the
	// exported key (no local repo, no state dir) re-clones from the host
	// ciphertext.
	exported := a.MustCloak("key", "export", "--key", "file:"+key, "--force-insecure")
	recoveredKey := filepath.Join(t.TempDir(), "recovered.key")
	r := harness.NewClient(t, "recovered", recoveredKey)
	if _, errb, err := r.CloakStdin(exported+"\n", "key", "import", "--key", "file:"+recoveredKey); err != nil {
		t.Fatalf("key import: %v\n%s", err, errb)
	}
	r.MustClone(host.Dir)
	if r.HeadOID() != want {
		t.Fatalf("recovered HEAD %s != original %s", r.HeadOID(), want)
	}
	if got, err := os.ReadFile(filepath.Join(r.Dir, "notes", "keep.md")); err != nil || string(got) != "important content\n" {
		t.Fatalf("recovered content wrong: %q err=%v", got, err)
	}
	if r.MustGit("rev-parse", "v1") != a.MustGit("rev-parse", "v1") {
		t.Fatal("tag v1 not recovered")
	}
}

// corruptHostBlob rewrites the blob at the tree path prefix into a tampered
// commit at the same chain position (same parent and generation-derived
// dates) so only the ciphertext changes.
func corruptHostBlob(t *testing.T, host *harness.Host, pathPrefix string, mutate func([]byte) []byte) {
	t.Helper()
	var target string
	for _, p := range host.LsTreeR("cloak") {
		if strings.HasPrefix(p, pathPrefix) {
			target = p
			break
		}
	}
	if target == "" {
		t.Fatalf("no blob under %q on host", pathPrefix)
	}
	blobOID := strings.Fields(host.Git("ls-tree", "cloak", target))[2]
	orig := []byte(host.GitRaw(t, "cat-file", "blob", blobOID))
	mutated := mutate(orig)
	if bytes.Equal(orig, mutated) {
		t.Fatal("mutation was a no-op")
	}
	newBlob := host.HashObjectStdin(t, mutated)
	host.ReplaceTreeEntry(t, "cloak", target, newBlob)
}

// assertCloneTamperNoObjects clones with the right key and asserts the
// clone fails with a tamper alarm and indexes no objects.
func assertCloneTamperNoObjects(t *testing.T, host *harness.Host, key string) {
	t.Helper()
	c := harness.NewClient(t, "victim", key)
	_, stderr, err := c.Git("clone", "cloak::"+host.Dir, c.Dir)
	if err == nil {
		t.Fatal("clone of tampered remote succeeded")
	}
	if !strings.Contains(stderr, "TAMPER ALARM") {
		t.Fatalf("corruption not reported as tamper: %s", stderr)
	}
	packDir := filepath.Join(c.Dir, ".git", "objects", "pack")
	entries, _ := os.ReadDir(packDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pack") || strings.HasSuffix(e.Name(), ".idx") {
			t.Fatalf("tampered data was indexed into the local object store: %s", e.Name())
		}
	}
}
