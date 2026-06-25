// Regression tests asserting that the engine's fetch/decrypt/push scratch-file
// IO leaf errors carry operation+filename context (objective clause 2: every
// error wrapped with context). A bare os.PathError already embeds the path, so
// each case asserts the specific operation phrase the wrap adds -- which a bare
// error does NOT carry -- and that the cause chain is preserved (%w, not %v).
package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

func TestScratchIOErrorsCarryContext(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newMachine(t, g, host, key).e
	tmp := e.St.TmpDir()

	// A directory planted where a scratch file is created makes open-for-write
	// fail deterministically (EISDIR); a missing path makes open-for-read fail
	// (ENOENT). Both reach the leaf IO branch before any backend/crypto work.
	blockedDir := filepath.Join(tmp, "blocked-dir")
	if err := os.Mkdir(blockedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(tmp, "does-not-exist")
	pack := manifest.Pack{ID: strings.Repeat("a", 64)}

	cases := []struct {
		name   string
		run    func() error
		phrase string
	}{
		{"downloadVerifyPack create ciphertext", func() error {
			return e.downloadVerifyPack("HEAD", blockedDir, pack)
		}, `create pack ciphertext scratch file`},
		{"decryptPackTo open ciphertext", func() error {
			return e.decryptPackTo(missing, filepath.Join(tmp, "out.pack"))
		}, `open pack ciphertext scratch file`},
		{"indexPackFile open plaintext", func() error {
			_, err := e.indexPackFile(missing, "abcdef012345", 0)
			return err
		}, `open pack plaintext scratch file`},
		{"hashPackBlob open ciphertext", func() error {
			_, err := e.hashPackBlob(missing)
			return err
		}, `open pack ciphertext scratch file`},
		{"indexPackInto open ciphertext", func() error {
			return e.indexPackInto(host, "HEAD", manifest.Pack{ID: pack.ID}, missing)
		}, `open pack ciphertext scratch file`},
	}
	for _, c := range cases {
		err := c.run()
		if err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.phrase) {
			t.Errorf("%s: error %q lacks operation context %q", c.name, err, c.phrase)
		}
		if errors.Unwrap(err) == nil {
			t.Errorf("%s: error %q does not preserve its cause (use %%w)", c.name, err)
		}
	}
}
