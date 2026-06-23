// A corrupt rollback pin must fail closed: CheckPin returns an error
// rather than silently reading as "no pin" (which would downgrade an
// established remote to trust-on-first-use and disable rollback
// protection). The pin file is the local anchor against a host serving
// stale or replayed state.
package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

func writePin(t *testing.T, d *Dir, raw string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(d.Root, pinFile), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptPinFailsClosed(t *testing.T) {
	for _, raw := range []string{"garbage no numbers", "", "   ", "notanumber hash"} {
		d := openDir(t)
		writePin(t, d, raw)

		if _, ok, err := d.LoadPin(); err == nil || ok {
			t.Errorf("LoadPin(%q): ok=%v err=%v, want ok=false err!=nil", raw, ok, err)
		}

		m := manifest.New()
		m.Generation = 5
		if err := d.CheckPin(m, "deadbeef"); err == nil {
			t.Errorf("CheckPin with corrupt pin %q accepted the remote (should fail closed)", raw)
		}
	}
}

func TestPartialPinMissingHashFailsClosed(t *testing.T) {
	d := openDir(t)
	writePin(t, d, "7") // generation but no manifest hash
	if _, ok, err := d.LoadPin(); err == nil || ok {
		t.Fatalf("LoadPin of generation-only pin: ok=%v err=%v, want failure", ok, err)
	}
}
