// Engine tests against a local bare "host" repository (no network): the
// full push/fetch round trip between two machines, per-ref decisions
// (fetch first, non-fast-forward, force, delete), rollback alarming,
// geometric consolidation, and FullRepack converging after losing the
// compare-and-swap to a concurrent push.
package engine

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/config"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/state"
)

// machine is one side of the sync: a plain local repository with worktree,
// its per-remote state, and an engine wired to the shared host.
type machine struct {
	e      *Engine
	g      *gitx.G
	dir    string
	gitDir string
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func newHostRepo(t *testing.T, g *gitx.G) string {
	t.Helper()
	host := filepath.Join(t.TempDir(), "host.git")
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--bare", "--initial-branch", "cloak", host); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: host}, "config", "uploadpack.allowfilter", "true"); err != nil {
		t.Fatal(err)
	}
	return host
}

func newMachine(t *testing.T, g *gitx.G, host string, key keystore.Key) *machine {
	t.Helper()
	dir := t.TempDir()
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--initial-branch", "main", dir); err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(dir, ".git")
	for _, kv := range [][2]string{{"user.name", "cloak-test"}, {"user.email", "t@t"}} {
		if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "config", kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	st, err := state.Open(gitDir, "origin", host)
	if err != nil {
		t.Fatal(err)
	}
	be, err := backend.Open(g, st.BackendGitDir(), host, "cloak", discard())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.GeometricFactor = 0 // tests opt in explicitly
	return &machine{
		e: &Engine{G: g, LocalGitDir: gitDir, St: st, Be: be, Key: key, Cfg: cfg, Log: discard()},
		g: g, dir: dir, gitDir: gitDir,
	}
}

// commit writes a file and commits it, returning the new HEAD oid.
func (m *machine) commit(t *testing.T, file, content string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(m.dir, file), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.g.Run(gitx.Opts{Dir: m.dir, Scrub: true}, "add", "-A"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.g.Run(gitx.Opts{Dir: m.dir, Scrub: true}, "commit", "-q", "-m", "add "+file); err != nil {
		t.Fatal(err)
	}
	oid, err := m.g.Out(gitx.Opts{Dir: m.dir}, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

func (m *machine) load(t *testing.T) *RemoteState {
	t.Helper()
	rs, err := m.e.LoadRemoteState()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func (m *machine) push(t *testing.T, rs *RemoteState, updates ...RefUpdate) ([]RefResult, *RemoteState) {
	t.Helper()
	results, newRS, err := m.e.Push(rs, updates, false)
	if err != nil {
		t.Fatal(err)
	}
	return results, newRS
}

const mainRef = "refs/heads/main"

func TestEnginePushFetchRoundTrip(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}

	a := newMachine(t, g, host, key)
	oid1 := a.commit(t, "f1.txt", "hello from a")
	rsA := a.load(t)
	if rsA.Manifest != nil {
		t.Fatal("fresh host not seen as empty")
	}
	results, rsA := a.push(t, rsA, RefUpdate{Src: mainRef, Dst: mainRef})
	if results[0].Err != "" {
		t.Fatalf("push rejected: %s", results[0].Err)
	}
	if rsA.Manifest.Generation != 1 || rsA.Manifest.Refs[mainRef] != oid1 || len(rsA.Manifest.Packs) != 1 {
		t.Fatalf("post-push manifest = %+v", rsA.Manifest)
	}
	if rsA.Manifest.Head != mainRef {
		t.Fatalf("manifest head = %q, want %s", rsA.Manifest.Head, mainRef)
	}

	b := newMachine(t, g, host, key)
	rsB := b.load(t)
	if rsB.Manifest.Generation != 1 || rsB.Manifest.Refs[mainRef] != oid1 {
		t.Fatalf("b sees manifest %+v", rsB.Manifest)
	}
	if _, err := b.e.FetchApply(rsB); err != nil {
		t.Fatal(err)
	}
	if !b.e.HaveObject(oid1) {
		t.Fatal("b did not receive the pushed object")
	}
}

func TestEnginePushRefDecisions(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, _ := keystore.Generate()

	a := newMachine(t, g, host, key)
	a.commit(t, "f1.txt", "from a")
	a.push(t, a.load(t), RefUpdate{Src: mainRef, Dst: mainRef})

	// B commits divergent history and pushes before fetching: the old tip
	// is unknown locally, so the decision must be "fetch first".
	b := newMachine(t, g, host, key)
	oid2b := b.commit(t, "f2.txt", "from b, divergent")
	rsB := b.load(t)
	results, rsB := b.push(t, rsB, RefUpdate{Src: mainRef, Dst: mainRef})
	if results[0].Err != "fetch first" {
		t.Fatalf("pre-fetch push decision = %q, want fetch first", results[0].Err)
	}

	if _, err := b.e.FetchApply(rsB); err != nil {
		t.Fatal(err)
	}
	results, rsB = b.push(t, rsB, RefUpdate{Src: mainRef, Dst: mainRef})
	if results[0].Err != "non-fast-forward" {
		t.Fatalf("divergent push decision = %q, want non-fast-forward", results[0].Err)
	}

	results, rsB = b.push(t, rsB, RefUpdate{Src: mainRef, Dst: mainRef, Force: true})
	if results[0].Err != "" {
		t.Fatalf("forced push rejected: %s", results[0].Err)
	}
	if rsB.Manifest.Refs[mainRef] != oid2b || rsB.Manifest.Generation != 2 {
		t.Fatalf("post-force manifest = %+v", rsB.Manifest)
	}

	// Deleting a missing ref is an error result; deleting main empties refs.
	results, rsB = b.push(t, rsB, RefUpdate{Src: "", Dst: "refs/heads/nope"})
	if results[0].Err == "" {
		t.Fatal("delete of a missing remote ref reported ok")
	}
	results, rsB = b.push(t, rsB, RefUpdate{Src: "", Dst: mainRef})
	if results[0].Err != "" || len(rsB.Manifest.Refs) != 0 {
		t.Fatalf("delete failed: %v, refs %v", results[0].Err, rsB.Manifest.Refs)
	}
}

func TestEngineRollbackAlarm(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, _ := keystore.Generate()

	a := newMachine(t, g, host, key)
	a.commit(t, "f1.txt", "one")
	rs := a.load(t)
	_, rs1 := a.push(t, rs, RefUpdate{Src: mainRef, Dst: mainRef})
	a.commit(t, "f2.txt", "two")
	_, rs2 := a.push(t, rs1, RefUpdate{Src: mainRef, Dst: mainRef})
	if rs2.Manifest.Generation != 2 {
		t.Fatalf("generation = %d, want 2", rs2.Manifest.Generation)
	}

	// Host rolls the backend branch back to generation 1.
	if _, _, err := g.Run(gitx.Opts{GitDir: host}, "update-ref", "refs/heads/cloak", rs1.Head); err != nil {
		t.Fatal(err)
	}
	_, err := a.e.LoadRemoteState()
	if err == nil {
		t.Fatal("rolled-back remote accepted")
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Rollback {
		t.Fatalf("rollback classified as %v, want Rollback (err: %v)", kind, err)
	}
}

func TestEngineGeometricConsolidation(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, _ := keystore.Generate()

	a := newMachine(t, g, host, key)
	a.e.Cfg.GeometricFactor = 4
	a.commit(t, "f1.txt", "first file with some content in it")
	rs := a.load(t)
	_, rs = a.push(t, rs, RefUpdate{Src: mainRef, Dst: mainRef})
	if len(rs.Manifest.Packs) != 1 {
		t.Fatalf("packs after first push = %d", len(rs.Manifest.Packs))
	}

	oid2 := a.commit(t, "f2.txt", "second file of comparable size here")
	_, rs = a.push(t, rs, RefUpdate{Src: mainRef, Dst: mainRef})
	if len(rs.Manifest.Packs) != 1 {
		t.Fatalf("consolidation did not run: %d live packs", len(rs.Manifest.Packs))
	}
	if got := len(rs.Manifest.Packs[0].Replaces); got != 2 {
		t.Fatalf("merged pack Replaces %d ids, want 2", got)
	}

	// A fresh machine must reconstruct everything from the merged pack.
	b := newMachine(t, g, host, key)
	rsB := b.load(t)
	if _, err := b.e.FetchApply(rsB); err != nil {
		t.Fatal(err)
	}
	if !b.e.HaveObject(oid2) {
		t.Fatal("merged pack did not deliver the second commit")
	}
}

// TestRejectedBackendPushLeavesPinUnadvanced locks in the crash-safety
// invariant that guards the dangerous direction of an interrupted push: the
// durable rollback pin is advanced only after the backend accepts (the PushOK
// arm), never before. If a failed push could move the pin ahead of the
// backend-accepted generation, the next fetch would see a lower remote
// generation and raise a false ROLLBACK ALARM. Iter6's self-heal test covers
// only the benign direction (pin left *behind* the backend); this covers the
// other half. A reaches the backend but loses the compare-and-swap to B's
// concurrent push (retries disabled so the loss is terminal); the push must
// fail and leave A's on-disk pin byte-for-byte where its last accepted push
// left it.
func TestRejectedBackendPushLeavesPinUnadvanced(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, _ := keystore.Generate()

	a := newMachine(t, g, host, key)
	a.e.Cfg.PushRetries = 0 // one attempt: a lost CAS is terminal, not retried
	oid1 := a.commit(t, "f1.txt", "base")
	_, rsA := a.push(t, a.load(t), RefUpdate{Src: mainRef, Dst: mainRef})
	if rsA.Manifest.Generation != 1 {
		t.Fatalf("first push generation = %d, want 1", rsA.Manifest.Generation)
	}
	pinBefore, ok, err := a.e.St.LoadPin()
	if err != nil || !ok {
		t.Fatalf("pin after first push: ok=%v err=%v", ok, err)
	}

	// B fetches, builds a child commit via plumbing, and pushes it: the backend
	// advances to generation 2 while A still holds its stale generation-1 view.
	b := newMachine(t, g, host, key)
	rsB := b.load(t)
	if _, err := b.e.FetchApply(rsB); err != nil {
		t.Fatal(err)
	}
	tree, err := g.Out(gitx.Opts{GitDir: b.gitDir}, "rev-parse", oid1+"^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	oid2, err := g.Out(gitx.Opts{GitDir: b.gitDir}, "commit-tree", tree, "-p", oid1, "-m", "from b")
	if err != nil {
		t.Fatal(err)
	}
	if results, _ := b.push(t, rsB, RefUpdate{Src: oid2, Dst: mainRef}); results[0].Err != "" {
		t.Fatalf("b push rejected: %s", results[0].Err)
	}

	// A pushes its own child of oid1 against its stale view: planning accepts it
	// (fast-forward from A's seen head) so the attempt reaches the backend, but
	// the branch has moved to B's commit, so the plain FF push loses the CAS and,
	// with retries disabled, the push terminates as CASExhausted.
	a.commit(t, "f3.txt", "from a")
	_, _, perr := a.e.Push(rsA, []RefUpdate{{Src: mainRef, Dst: mainRef}}, false)
	if perr == nil {
		t.Fatal("stale push unexpectedly succeeded")
	}
	if kind, ok := cloakerr.KindOf(perr); !ok || kind != cloakerr.CASExhausted {
		t.Fatalf("stale push error kind = %v, want CASExhausted (err: %v)", kind, perr)
	}

	// The rejected push must not have advanced the durable rollback pin: it is
	// still exactly the generation/hash the backend last accepted.
	pinAfter, ok, err := a.e.St.LoadPin()
	if err != nil || !ok {
		t.Fatalf("pin after rejected push: ok=%v err=%v", ok, err)
	}
	if pinAfter != pinBefore {
		t.Fatalf("rejected push advanced the pin: before %+v, after %+v", pinBefore, pinAfter)
	}
}

func TestFullRepackConvergesAfterConcurrentPush(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, _ := keystore.Generate()

	a := newMachine(t, g, host, key)
	oid1 := a.commit(t, "f1.txt", "base")
	rs := a.load(t)
	_, rsA := a.push(t, rs, RefUpdate{Src: mainRef, Dst: mainRef})

	// B fetches, builds a child commit via plumbing, and pushes it: the
	// remote moves to generation 2 while A still holds generation 1 state.
	b := newMachine(t, g, host, key)
	rsB := b.load(t)
	if _, err := b.e.FetchApply(rsB); err != nil {
		t.Fatal(err)
	}
	tree, err := g.Out(gitx.Opts{GitDir: b.gitDir}, "rev-parse", oid1+"^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	oid2, err := g.Out(gitx.Opts{GitDir: b.gitDir}, "commit-tree", tree, "-p", oid1, "-m", "from b")
	if err != nil {
		t.Fatal(err)
	}
	results, _ := b.push(t, rsB, RefUpdate{Src: oid2, Dst: mainRef})
	if results[0].Err != "" {
		t.Fatalf("b push rejected: %s", results[0].Err)
	}

	// A repacks with its stale view: the first lease push must lose the
	// compare-and-swap, and the retry must fetch and apply B's new pack
	// before re-packing, or pack-objects would not have oid2.
	rsNew, err := a.e.FullRepack(rsA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rsNew.Manifest.Generation != 3 {
		t.Fatalf("post-repack generation = %d, want 3", rsNew.Manifest.Generation)
	}
	if rsNew.Manifest.Refs[mainRef] != oid2 {
		t.Fatalf("repack lost the concurrent commit: main = %s, want %s",
			rsNew.Manifest.Refs[mainRef], oid2)
	}
	if len(rsNew.Manifest.Packs) != 1 || len(rsNew.Manifest.Packs[0].Replaces) != 2 {
		t.Fatalf("repack manifest packs = %+v", rsNew.Manifest.Packs)
	}
	if !a.e.HaveObject(oid2) {
		t.Fatal("a never applied the concurrent pack")
	}
}
