// In-process unit tests for the multi-pack push split path: buildPacks splits an
// over-limit push into several self-contained sub-limit packs, and refuses a
// single file whose encrypted pack alone exceeds the limit. These exercise the
// engine directly (no subprocess helper), so coverage is attributed in-process.
package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// incompressibleBytes returns n high-entropy bytes (xorshift from seed) so the
// packed/encrypted size tracks the byte count; distinct seeds yield blobs git
// will not delta-compress together, which is needed to force a multi-pack split.
func incompressibleBytes(seed uint32, n int) []byte {
	b := make([]byte, n)
	x := seed
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

func TestBuildPacksSplitsOversizedPush(t *testing.T) {
	g := gitx.New(discard())
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newMachine(t, g, newHostRepo(t, g), key)
	const limit = 2 << 20 // 2 MiB per-file cap
	a.e.Cfg.MaxPackBytes = limit

	// Four distinct ~1 MiB incompressible files: each fits, but together they
	// exceed the limit, so buildPacks must split into several sub-limit packs.
	var head string
	for i, name := range []string{"a.bin", "b.bin", "c.bin", "d.bin"} {
		head = a.commit(t, name, string(incompressibleBytes(uint32(i+1)*2654435761, 1<<20)))
	}

	packs, err := a.e.buildPacks([]string{head}, map[string]string{})
	if err != nil {
		t.Fatalf("buildPacks: %v", err)
	}
	t.Cleanup(func() {
		for _, p := range packs {
			_ = os.Remove(p.path)
		}
	})

	if len(packs) < 2 {
		t.Fatalf("oversized push not split: got %d pack(s), want >= 2", len(packs))
	}
	for _, p := range packs {
		if p.size > limit {
			t.Fatalf("split pack %.12s over limit: %d > %d", p.id, p.size, limit)
		}
		if !p.applied {
			t.Fatalf("freshly built split pack %.12s not marked applied", p.id)
		}
		assertPackSelfContained(t, g, key, p.path)
	}
}

// assertPackSelfContained decrypts the ciphertext pack and indexes it into a
// fresh EMPTY bare repo exactly as fetch does (index-pack --stdin, no --strict):
// that resolves the pack's deltas without any other object present, so a thin
// pack (a delta whose base lives in a sibling pack) would fail with a missing
// base. Success proves the pack is non-thin -- the property fetch relies on when
// it applies each pack independently. (--strict is deliberately omitted: it adds
// an fsck connectivity check that a single pack of a multi-pack set cannot
// satisfy, since it references commits/trees/blobs held in sibling packs.)
func assertPackSelfContained(t *testing.T, g *gitx.G, key keystore.Key, ctPath string) {
	t.Helper()
	ct, err := os.Open(ctPath) // #nosec G304 -- test-controlled TmpDir ciphertext path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ct.Close() }()
	plain, err := agecrypt.Decrypt(ct, key)
	if err != nil {
		t.Fatalf("decrypt pack: %v", err)
	}
	bare := filepath.Join(t.TempDir(), "verify.git")
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--bare", "--quiet", bare); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: bare, Stdin: plain}, "index-pack", "--stdin"); err != nil {
		t.Fatalf("split pack %q is thin (index-pack into empty repo failed): %v", ctPath, err)
	}
}

func TestBuildPacksRefusesSingleOversizeFile(t *testing.T) {
	g := gitx.New(discard())
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newMachine(t, g, newHostRepo(t, g), key)
	a.e.Cfg.MaxPackBytes = 2 << 20

	// One 3 MiB incompressible file: its pack alone exceeds the 2 MiB cap, which
	// no split can fix, so buildPacks must refuse with the single-file error.
	head := a.commit(t, "huge.bin", string(incompressibleBytes(99, 3<<20)))

	_, err = a.e.buildPacks([]string{head}, map[string]string{})
	if err == nil {
		t.Fatal("single over-limit file should be refused")
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.TooLarge {
		t.Fatalf("error not classified TooLarge: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "push blocked") || !strings.Contains(msg, "per-file limit") {
		t.Fatalf("residual error not the single-file message: %q", msg)
	}
	if !strings.Contains(msg, "huge.bin") {
		t.Fatalf("residual error did not name the offending file: %q", msg)
	}
}
