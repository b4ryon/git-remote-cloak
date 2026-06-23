// End-to-end repo-identity and pin-ordering security properties:
//   - a host that substitutes another same-key repository's genuine manifest
//     (a different bound repo id) is rejected, closing cross-repo substitution;
//   - a host that serves a valid higher-generation manifest while withholding
//     or corrupting its pack does NOT advance the local rollback pin, and an
//     honest fetch afterwards is accepted with no false rollback alarm.
package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestCrossRepoSubstitutionRejected(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)

	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	a.WriteFile("f.md", "real content\n")
	a.Commit("c0")
	a.MustGit("remote", "add", "origin", "cloak::"+host.Dir)
	a.MustGit("push", "-u", "origin", "main")
	realOID := a.HeadOID()

	// The victim clones, pinning THIS repository's identity (trust-on-first-use).
	victim := harness.NewClient(t, "victim", key)
	victim.MustClone(host.Dir)

	var packID string
	for _, p := range host.LsTreeR("cloak") {
		if strings.HasPrefix(p, "packs/") {
			packID = strings.TrimSuffix(strings.TrimPrefix(p, "packs/"), ".age")
		}
	}
	if packID == "" {
		t.Fatal("no pack found on host")
	}

	// A manifest validly encrypted under the SAME shared key but bound to a
	// DIFFERENT repo id (as another same-key repository's genuine manifest
	// would be), at a higher generation so the rollback pin passes.
	substitute := `{"version":1,"repo_id":"ffffffffffffffffffffffffffffffff","generation":2,` +
		`"head":"refs/heads/main","refs":{"refs/heads/main":"` + realOID + `"},` +
		`"packs":[{"id":"` + packID + `","size":1}]}`
	blob := encryptUnder(t, a, key, substitute)
	oid := host.HashObjectStdin(t, blob)
	host.ReplaceTreeEntry(t, "cloak", "manifest.age", oid)

	_, stderr, err := victim.Git("fetch", "origin")
	if err == nil {
		t.Fatal("fetch accepted a manifest bound to a different repo id")
	}
	if !strings.Contains(stderr, "REPO IDENTITY MISMATCH") {
		t.Fatalf("cross-repo substitution not reported as a repo-identity mismatch: %s", stderr)
	}
}

func TestWithheldPackDoesNotAdvancePin(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)

	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	a.MustGit("config", "cloak.geometricFactor", "0") // keep the two packs separate
	a.WriteFile("a.md", strings.Repeat("alpha ", 500))
	a.Commit("c0")
	a.MustGit("remote", "add", "origin", "cloak::"+host.Dir)
	a.MustGit("push", "-u", "origin", "main")

	victim := harness.NewClient(t, "victim", key)
	victim.MustClone(host.Dir) // pins generation 1, applies the gen-1 pack
	if got := pinGeneration(t, victim); got != 1 {
		t.Fatalf("victim pinned generation %d after clone, want 1", got)
	}

	packsBefore := map[string]bool{}
	for _, p := range host.LsTreeR("cloak") {
		packsBefore[p] = true
	}

	// a pushes generation 2 with a new, separate pack.
	a.WriteFile("b.md", strings.Repeat("beta ", 500))
	a.Commit("c1")
	a.MustGit("push", "origin", "main")
	honestTip := host.Git("rev-parse", "cloak")

	var gen2Pack string
	for _, p := range host.LsTreeR("cloak") {
		if strings.HasPrefix(p, "packs/") && !packsBefore[p] {
			gen2Pack = p
		}
	}
	if gen2Pack == "" {
		t.Fatal("could not identify the generation-2 pack")
	}

	// Corrupt the new pack: its ciphertext no longer hashes to its manifest id.
	garbage := host.HashObjectStdin(t, []byte("not valid ciphertext"))
	host.ReplaceTreeEntry(t, "cloak", gen2Pack, garbage)

	// The fetch must fail closed (tamper) and must NOT advance the pin.
	if _, stderr, err := victim.Git("fetch", "origin"); err == nil {
		t.Fatal("fetch accepted a corrupted pack")
	} else if !strings.Contains(stderr, "TAMPER ALARM") {
		t.Fatalf("corrupt pack not reported as tamper: %s", stderr)
	}
	if got := pinGeneration(t, victim); got != 1 {
		t.Fatalf("pin advanced to %d despite a failed apply (want 1)", got)
	}

	// Restore the honest generation-2 state: the victim now fetches cleanly
	// with NO false rollback alarm, and the pin advances.
	host.Git("update-ref", "refs/heads/cloak", honestTip)
	if out, stderr, err := victim.Git("fetch", "origin"); err != nil {
		t.Fatalf("honest fetch after a withheld pack failed: %v\n%s\n%s", err, out, stderr)
	}
	if got := pinGeneration(t, victim); got != 2 {
		t.Fatalf("pin did not advance to 2 after the honest fetch (got %d)", got)
	}
}

// pinGeneration reads the rollback pin's generation from the client's only
// per-remote state directory.
func pinGeneration(t *testing.T, c *harness.Client) int {
	t.Helper()
	root := filepath.Join(c.Dir, ".git", "cloak")
	gen := -1
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && filepath.Base(path) == "generation" {
			if b, rerr := os.ReadFile(path); rerr == nil {
				fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &gen)
			}
		}
		return nil
	})
	if gen < 0 {
		t.Fatalf("no generation pin file under %s", root)
	}
	return gen
}
