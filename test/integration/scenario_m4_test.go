// M4 scenarios from the DESIGN.md testing plan: 6 (geometric consolidation
// squashes the chain; consolidation lineage lets an up-to-date client skip
// re-downloading the repacked history) and 7 (full repack and rekey; the
// old key fails closed, clients with the new key pull cleanly).
package integration

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

// bigPushSetup pushes one large initial commit so small pushes sit in a
// lower geometric tier than the base pack.
func bigPushSetup(t *testing.T) (*harness.Host, string, *harness.Client) {
	t.Helper()
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	var big strings.Builder
	for i := 0; i < 6000; i++ {
		fmt.Fprintf(&big, "line %d: varied content %x %d\n", i, i*7919, i*i)
	}
	a.WriteFile("big.md", big.String())
	a.Commit("c0")
	a.MustGit("remote", "add", "origin", "cloak::"+host.Dir)
	a.MustGit("push", "-u", "origin", "main")
	return host, key, a
}

func smallPush(t *testing.T, a *harness.Client, name string) {
	t.Helper()
	a.WriteFile(name, "small edit "+name+"\n")
	a.Commit("edit " + name)
	a.MustGit("push", "origin", "main")
}

func TestScenario6ConsolidationAndReplaces(t *testing.T) {
	host, key, a := bigPushSetup(t)

	// Two small pushes: the second one violates the factor-2 invariant
	// against the first, triggering consolidation + squash mid-push.
	smallPush(t, a, "s1.md")
	smallPush(t, a, "s2.md")

	if got := host.Git("rev-list", "--count", "cloak"); got != "1" {
		t.Fatalf("backend chain not squashed by consolidation: %s commits", got)
	}
	if packs := hostPackSizes(t, host); len(packs) != 2 {
		t.Fatalf("pack count after consolidation = %d, want 2 (base + merged tier)", len(packs))
	}
	if !strings.Contains(a.DebugLog(), "geometric consolidation triggered") {
		t.Fatal("consolidation did not log its trigger")
	}

	// C catches up fully, then A pushes one more small pack and runs a
	// full repack. C's next fetch must skip downloading the repack pack
	// (its Replaces are all applied) and only take the small new one.
	c := harness.NewClient(t, "c", key)
	c.MustClone(host.Dir)
	smallPush(t, a, "s3.md")
	c.MustGit("pull", "origin", "main")
	preApplied := strings.Count(c.DebugLog(), `"msg":"applied pack"`)

	out := a.MustCloak("repack", "--remote", "origin")
	if !strings.Contains(out, "Repacked") {
		t.Fatalf("repack output: %q", out)
	}
	if got := host.Git("rev-list", "--count", "cloak"); got != "1" {
		t.Fatalf("repack did not squash the chain: %s commits", got)
	}
	if packs := hostPackSizes(t, host); len(packs) != 1 {
		t.Fatalf("pack count after repack = %d, want 1", len(packs))
	}

	smallPush(t, a, "s4.md")
	c.MustGit("pull", "origin", "main")
	if c.HeadOID() != a.HeadOID() {
		t.Fatalf("C did not converge after repack: %s != %s", c.HeadOID(), a.HeadOID())
	}
	postApplied := strings.Count(c.DebugLog(), `"msg":"applied pack"`)
	if postApplied != preApplied+1 {
		t.Fatalf("C applied %d new packs after repack, want exactly 1 (the s4 pack); repack pack was re-downloaded",
			postApplied-preApplied)
	}
	if !strings.Contains(c.DebugLog(), "covered by applied predecessors") {
		t.Fatal("consolidation lineage (Replaces) skip path never ran on C")
	}
}

func TestScenario7RepackRekey(t *testing.T) {
	host, key, a := pushSetup(t)
	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)

	k2 := filepath.Join(t.TempDir(), "k2")
	a.MustCloak("keygen", "--key", "file:"+k2)
	out := a.MustCloak("rekey", "--remote", "origin", "--new-key", "file:"+k2)
	if !strings.Contains(out, "Rekeyed") {
		t.Fatalf("rekey output: %q", out)
	}
	if packs := hostPackSizes(t, host); len(packs) != 1 {
		t.Fatalf("pack count after rekey = %d, want 1", len(packs))
	}

	// A works under the new key (rekey updated its repo config).
	a.WriteFile("after-rekey.md", "new key content\n")
	a.Commit("after rekey")
	a.MustGit("push", "origin", "main")

	// B still holds the old key: must fail closed with a tamper alarm.
	_, stderr, err := b.Git("pull", "origin", "main")
	if err == nil {
		t.Fatal("pull with the old key succeeded after rekey")
	}
	if !strings.Contains(stderr, "TAMPER ALARM") {
		t.Fatalf("old-key failure not reported as tamper: %s", stderr)
	}

	// B imports the new key and recovers.
	b.MustGit("config", "cloak.keyRef", "file:"+k2)
	b.MustGit("pull", "origin", "main")
	if b.HeadOID() != a.HeadOID() {
		t.Fatalf("B did not converge after key switch: %s != %s", b.HeadOID(), a.HeadOID())
	}
}
