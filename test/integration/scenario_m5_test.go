// M5 scenarios from the DESIGN.md testing plan: 4 (rollback injection ->
// alarm -> accept-rollback recovery), 5 (ciphertext corruption of a pack
// and the manifest reported as tamper and never applied), and 8 (recovery
// of a clone from remote ciphertext plus only the exported key).
package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
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

// TestInterruptedPersistSelfHeals proves the crash-safety property the atomic
// state writes exist to guarantee: an interrupted push that committed the
// backend but never landed its local pin update (a crash between the backend
// push and SavePin) leaves the local pin behind the backend, and that residue
// must self-heal -- the next push accepts the higher remote generation, lands,
// and re-pins, with no false rollback alarm and no manual intervention.
//
// This is the benign inverse of TestScenario4RollbackInjection: there the
// BACKEND regresses below the local pin (a real rollback) and must ALARM; here
// the LOCAL PIN regresses below the backend (crash residue) and must be
// silently corrected. The asymmetry is the whole point of the pin -- a pin
// behind the truth is harmless and auto-corrects, a backend behind the pin is
// an attack -- so an interrupted push can never leave state that blocks or
// corrupts the next one.
func TestInterruptedPersistSelfHeals(t *testing.T) {
	host, key, a := pushSetup(t)

	// Snapshot the pin exactly as it stood after the first push.
	pinV1, err := os.ReadFile(pinFilePath(t, a))
	if err != nil {
		t.Fatal(err)
	}
	staleGen := pinGeneration(t, a)

	// A pushes a second generation; the backend and the local pin both advance.
	a.WriteFile("more.md", "second push\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")
	if g := pinGeneration(t, a); g <= staleGen {
		t.Fatalf("second push did not advance the pin: %d <= %d", g, staleGen)
	}

	// Model the crash: the second push's backend commit landed, but its SavePin
	// was interrupted, so on disk the pin still reflects the first generation
	// while the backend is a generation ahead.
	if err := os.WriteFile(pinFilePath(t, a), pinV1, 0o600); err != nil {
		t.Fatal(err)
	}
	if g := pinGeneration(t, a); g != staleGen {
		t.Fatalf("pin-regression injection did not take effect: %d != %d", g, staleGen)
	}

	// The next push must self-heal: LoadRemoteState's CheckPin sees the higher
	// remote generation and accepts (no rollback alarm), the push lands, and
	// persistPushed re-pins past the stale residue.
	a.WriteFile("third.md", "third push\n")
	a.Commit("c2")
	out, stderr, err := a.Git("push", "origin", "main")
	if err != nil {
		t.Fatalf("push after interrupted persist failed (state did not self-heal): %v\nstdout: %s\nstderr: %s", err, out, stderr)
	}
	if strings.Contains(stderr, "ALARM") {
		t.Fatalf("interrupted persist raised a false alarm on the next push: %s", stderr)
	}
	if g := pinGeneration(t, a); g <= staleGen {
		t.Fatalf("pin did not self-heal: generation still %d (expected past the stale %d)", g, staleGen)
	}

	// End-to-end: the recovered state is coherent -- a fresh clone reproduces
	// A's head exactly.
	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)
	if b.HeadOID() != a.HeadOID() {
		t.Fatalf("clone after self-heal HEAD %s != source %s", b.HeadOID(), a.HeadOID())
	}
}

// TestFailedFetchLeavesAppliedSetUnadvanced is the fetch-direction analog of
// TestRejectedBackendPushLeavesPinUnadvanced: it locks in the crash-safety
// invariant for the applied-set state file. A pack is recorded as applied only
// AFTER FetchApply indexes it; if the fetch aborts mid-apply (here forced by a
// corrupted pack, the same deterministic stand-in for an interruption that
// iter10 used a lost CAS for), the applied set must stay byte-for-byte
// unadvanced. Otherwise a crash could leave the applied set claiming a pack is
// present while its objects never landed, permanently skipping the re-download
// (the applied set is never re-examined) and silently corrupting the repo.
//
// Scenario5 already proves no git objects are indexed on a tampered pack, but
// that checks the git object store (.pack/.idx files), NOT the cloak applied
// state file -- a mark-before-apply reorder would leave no .pack yet still
// advance the applied set, passing scenario5 while corrupting the repo. This
// test closes that gap.
func TestFailedFetchLeavesAppliedSetUnadvanced(t *testing.T) {
	host, key, a := pushSetup(t)
	// Disable consolidation so the second push adds a distinct live pack rather
	// than a merged pack that Replaces the first -- B has the first applied, so
	// a merged pack would be skippable and never downloaded, never triggering
	// the corruption.
	a.MustGit("config", "cloak.geometricFactor", "0")

	// B clones at generation 1: it applies the first pack and pins generation 1.
	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)
	appliedPath := appliedFilePath(t, b)
	appliedBefore, err := os.ReadFile(appliedPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(string(appliedBefore))) == 0 {
		t.Fatalf("clone did not record any applied pack: %q", appliedBefore)
	}
	pinBefore := pinGeneration(t, b)

	// A pushes a second generation carrying a new, independent live pack that B
	// does not yet hold.
	a.WriteFile("more.md", "second push\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")

	// Corrupt exactly that un-applied pack on the host so B's fetch downloads it,
	// fails ciphertext verification, and aborts mid-apply.
	corruptUnappliedPack(t, host, appliedSetFromBytes(appliedBefore))

	// The fetch must fail closed as tamper ...
	if _, stderr, ferr := b.Git("fetch", "origin"); ferr == nil {
		t.Fatalf("fetch accepted a corrupted pack (should fail closed): %s", stderr)
	} else if !strings.Contains(stderr, "TAMPER ALARM") {
		t.Fatalf("corrupted pack not reported as tamper: %s", stderr)
	}

	// ... and must leave the applied-set state file byte-for-byte unadvanced:
	// the failed pack was never marked applied, so a crash here re-applies it
	// cleanly instead of permanently skipping an un-applied pack.
	appliedAfter, err := os.ReadFile(appliedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(appliedBefore, appliedAfter) {
		t.Fatalf("failed fetch advanced the applied set:\nbefore %q\nafter  %q", appliedBefore, appliedAfter)
	}
	// The rollback pin likewise stayed at generation 1: CommitPin runs only
	// after a fully applied fetch, so a failed fetch never advances it either.
	if g := pinGeneration(t, b); g != pinBefore {
		t.Fatalf("failed fetch advanced the pin: %d != %d", g, pinBefore)
	}
}

// appliedFilePath returns the client's single applied-set state file path,
// failing if there is not exactly one (the integration clients use a single
// remote).
func appliedFilePath(t *testing.T, c *harness.Client) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(c.Dir, ".git", "cloak", "*", "applied"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one applied state file, found %d: %v", len(matches), matches)
	}
	return matches[0]
}

// appliedSetFromBytes parses an applied-set state file's content (one pack id
// per line) into a lookup set.
func appliedSetFromBytes(b []byte) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if id := strings.TrimSpace(line); id != "" {
			out[id] = true
		}
	}
	return out
}

// corruptUnappliedPack flips a byte of the one host pack blob whose id is not
// already in applied, so a client holding the applied set must download it on
// the next fetch and hit the tampered ciphertext. Mirrors corruptHostBlob but
// targets a specific (not the first) pack.
func corruptUnappliedPack(t *testing.T, host *harness.Host, applied map[string]bool) {
	t.Helper()
	var target string
	for _, p := range host.LsTreeR("cloak") {
		if !strings.HasPrefix(p, "packs/") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(p, "packs/"), ".age")
		if !applied[id] {
			target = p
			break
		}
	}
	if target == "" {
		t.Fatal("no un-applied pack blob found on host to corrupt")
	}
	blobOID := strings.Fields(host.Git("ls-tree", "cloak", target))[2]
	orig := []byte(host.GitRaw(t, "cat-file", "blob", blobOID))
	mutated := append([]byte(nil), orig...)
	mutated[len(mutated)/2] ^= 0x01
	if bytes.Equal(orig, mutated) {
		t.Fatal("mutation was a no-op")
	}
	host.ReplaceTreeEntry(t, "cloak", target, host.HashObjectStdin(t, mutated))
}

// pinFilePath returns the client's single rollback pin file path, failing if
// there is not exactly one (the integration clients use a single remote).
func pinFilePath(t *testing.T, c *harness.Client) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(c.Dir, ".git", "cloak", "*", "generation"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one rollback pin file, found %d: %v", len(matches), matches)
	}
	return matches[0]
}

// pinGeneration parses the generation field (the first whitespace-delimited
// token, per the "generation hash" pin format) from the client's pin file.
func pinGeneration(t *testing.T, c *harness.Client) uint64 {
	t.Helper()
	b, err := os.ReadFile(pinFilePath(t, c))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		t.Fatalf("empty pin file: %q", b)
	}
	gen, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		t.Fatalf("unparseable pin generation %q: %v", fields[0], err)
	}
	return gen
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
