// Fuzz coverage for the version package's pure build-setting parser.
//
// vcsRevision is the last pure parser in the repo without fuzz coverage. It
// turns the build's []debug.BuildSetting (what `git cloak version` reports when
// no -ldflags version is stamped) into the short revision string, applying a
// 12-byte truncation and a "-dirty" suffix. FuzzVcsRevision pins that contract
// over arbitrary setting sequences against an independent oracle (reverse-scan
// for the last vcs.revision, existential scan for any vcs.modified=="true"),
// catching a forward/backward last-wins slip, an AND/OR error on the dirty
// flag, a dropped truncation, or a mishandled empty revision.
package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

// settingsFromFuzz decodes a fuzz blob into a build-setting slice. Each
// non-empty line is "KEY\tVALUE" (split on the first tab); a leading single
// selector ("r"/"m"/"t") is remapped to the meaningful build keys so the
// vcs.revision/vcs.modified branches are hit frequently, while any other key
// flows through verbatim as noise (and can still spell a real key directly).
func settingsFromFuzz(blob string) []debug.BuildSetting {
	var out []debug.BuildSetting
	for _, line := range strings.Split(blob, "\n") {
		if line == "" {
			continue
		}
		key, val, _ := strings.Cut(line, "\t")
		switch key {
		case "r":
			key = "vcs.revision"
		case "m":
			key = "vcs.modified"
		case "t":
			key = "vcs.time"
		}
		out = append(out, debug.BuildSetting{Key: key, Value: val})
	}
	return out
}

func FuzzVcsRevision(f *testing.F) {
	// Seeds: empty, clean short, truncating long, dirty, modified=false stays
	// clean, modified with no revision, last-revision-wins, noise-skipped,
	// any-modified-true wins over a prior false, and a multibyte revision that
	// forces byte (not rune) truncation.
	f.Add("")
	f.Add("r\tabc123")
	f.Add("r\t0123456789abcdef")
	f.Add("r\tabc123\nm\ttrue")
	f.Add("r\tabc123\nm\tfalse")
	f.Add("m\ttrue")
	f.Add("r\tfirst\nr\tsecond")
	f.Add("noise\tval\nr\tabc123")
	f.Add("m\tfalse\nm\ttrue")
	f.Add("r\t" + strings.Repeat("é", 8))

	f.Fuzz(func(t *testing.T, blob string) {
		settings := settingsFromFuzz(blob)

		got := vcsRevision(settings)

		// Independent oracle, derived by a different decomposition than the
		// implementation's single forward accumulating loop: the last
		// vcs.revision value (reverse scan) and whether ANY vcs.modified equals
		// exactly "true" (existential scan, never un-set).
		oracleRev := ""
		for i := len(settings) - 1; i >= 0; i-- {
			if settings[i].Key == "vcs.revision" {
				oracleRev = settings[i].Value
				break
			}
		}
		oracleDirty := ""
		for _, s := range settings {
			if s.Key == "vcs.modified" && s.Value == "true" {
				oracleDirty = "-dirty"
				break
			}
		}
		revPortion := oracleRev
		if len(revPortion) > 12 {
			revPortion = revPortion[:12]
		}
		want := ""
		if oracleRev != "" {
			want = revPortion + oracleDirty
		}

		if got != want {
			t.Fatalf("vcsRevision = %q, want %q (rev=%q dirty=%q)",
				got, want, oracleRev, oracleDirty)
		}

		// Empty-iff-no-revision: the result is empty exactly when no
		// vcs.revision value was recorded (including an empty value), so a
		// "-dirty" suffix can never leak without a revision to attach to.
		if (got == "") != (oracleRev == "") {
			t.Fatalf("emptiness mismatch: got %q, oracleRev %q", got, oracleRev)
		}

		if oracleRev != "" {
			// The revision portion (result minus any suffix) is always a byte
			// prefix of the recorded revision and never exceeds 12 bytes.
			core := strings.TrimSuffix(got, oracleDirty)
			if len(core) > 12 {
				t.Fatalf("revision portion %q exceeds 12 bytes", core)
			}
			if !strings.HasPrefix(oracleRev, core) {
				t.Fatalf("revision portion %q is not a prefix of %q", core, oracleRev)
			}
		}

		// Determinism: a pure parser must repeat on the same input.
		if again := vcsRevision(settings); again != got {
			t.Fatalf("vcsRevision not deterministic: %q then %q", got, again)
		}
	})
}
