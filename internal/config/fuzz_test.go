// Fuzz tests for the cloak.* config parser (applyConfigLines), the pure,
// side-effect-free consumer of `git config --get-regexp ^cloak\.` output that
// Load applies after running the git subprocess. The lines it parses are
// host/repo-influenced, so this parsing layer is worth fuzzing directly. Two
// targets: the robustness plus "documented default survives" safety contract
// over arbitrary output, and a faithful round trip asserting a user-set value
// is loaded back (the all-inputs generalization of TestLoadOverrides).
package config

import (
	"strconv"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// configSeeds exercise empty/blank input, well-formed settings, value-less and
// space-bearing values, out-of-range and unparseable numerics, unknown and
// mixed-case keys, and lines with no separating space.
var configSeeds = []string{
	"",
	"\n\n",
	"cloak.keyref file:/x/key",
	"cloak.geometricfactor 3\ncloak.pushretries 9",
	"cloak.branch vault\ncloak.loglevel debug",
	"cloak.geometricfactor -1\ncloak.pushretries zero",
	"cloak.geometricfactor 99999999999999999999",
	"cloak.branch ",
	"cloak.branch my vault name",
	"CLOAK.BRANCH MixedCase",
	"cloak.unknown whatever\nnotcloak.x y",
	"novalueline",
	"cloak.pushretries 0\ncloak.geometricfactor 0",
}

func FuzzApplyConfigLines(f *testing.F) {
	for _, s := range configSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		c := Defaults()
		applyConfigLines(&c, out)

		// "documented default survives": out-of-range numerics and an empty
		// branch can never break these load-bearing invariants. A negative
		// GeometricFactor would feed garbage to geometry.Victims, a PushRetries
		// below 1 would make the CAS push loop attempt nothing, and an empty
		// Branch is not a valid backend ref - the parser must never produce them.
		if c.GeometricFactor < 0 {
			t.Fatalf("GeometricFactor went negative: %d\ninput: %q", c.GeometricFactor, out)
		}
		if c.PushRetries < 1 {
			t.Fatalf("PushRetries dropped below 1: %d\ninput: %q", c.PushRetries, out)
		}
		if c.Branch == "" {
			t.Fatalf("Branch became empty\ninput: %q", out)
		}

		// Parsing is deterministic: the same output always yields the same
		// config from a fresh Defaults().
		c2 := Defaults()
		applyConfigLines(&c2, out)
		if c != c2 {
			t.Fatalf("non-deterministic parse:\n a: %+v\n b: %+v\ninput: %q", c, c2, out)
		}

		// Parsing is idempotent: re-applying the same lines to the already
		// parsed config changes nothing, since each setting is a pure function
		// of the input and a second pass re-derives identical values.
		c3 := c
		applyConfigLines(&c3, out)
		if c3 != c {
			t.Fatalf("not idempotent:\n once:  %+v\n twice: %+v\ninput: %q", c, c3, out)
		}
	})
}

// FuzzConfigRoundTrip builds the `git config --get-regexp` output that setting
// each cloak.* key to a fuzzed value would produce, then asserts
// applyConfigLines loads those values back per the documented gates.
func FuzzConfigRoundTrip(f *testing.F) {
	f.Add("file:/k", "vault", "debug", 3, 9)
	f.Add("", "", "", -1, 0)
	f.Add("keychain:cloak", "my vault", "warn", 0, 1)
	f.Add("file:/k\ninjected", "b", "l", 2, 5)
	f.Fuzz(func(t *testing.T, keyRef, branch, logLevel string, factor, retries int) {
		// A value with a line break or surrounding whitespace cannot be carried
		// on one `key value` line, so the round trip only holds for "clean"
		// values; unclean ones are covered by FuzzApplyConfigLines.
		if !clean(keyRef) || !clean(branch) || !clean(logLevel) {
			return
		}

		var b strings.Builder
		if keyRef != "" {
			b.WriteString("cloak.keyref " + keyRef + "\n")
		}
		b.WriteString("cloak.geometricfactor " + strconv.Itoa(factor) + "\n")
		b.WriteString("cloak.pushretries " + strconv.Itoa(retries) + "\n")
		if branch != "" {
			b.WriteString("cloak.branch " + branch + "\n")
		}
		if logLevel != "" {
			b.WriteString("cloak.loglevel " + logLevel + "\n")
		}

		c := Defaults()
		applyConfigLines(&c, b.String())

		// String settings: a non-empty value is loaded verbatim; an empty value
		// emits no line so the documented default stands.
		wantKeyRef := keystore.DefaultRef()
		if keyRef != "" {
			wantKeyRef = keyRef
		}
		if c.KeyRef != wantKeyRef {
			t.Fatalf("KeyRef: got %q want %q", c.KeyRef, wantKeyRef)
		}
		wantBranch := "cloak"
		if branch != "" {
			wantBranch = branch
		}
		if c.Branch != wantBranch {
			t.Fatalf("Branch: got %q want %q", c.Branch, wantBranch)
		}
		wantLog := "info"
		if logLevel != "" {
			wantLog = logLevel
		}
		if c.LogLevel != wantLog {
			t.Fatalf("LogLevel: got %q want %q", c.LogLevel, wantLog)
		}

		// Numeric settings apply only inside their documented range; otherwise
		// the default survives (GeometricFactor >= 0, PushRetries >= 1).
		wantFactor := 2
		if factor >= 0 {
			wantFactor = factor
		}
		if c.GeometricFactor != wantFactor {
			t.Fatalf("GeometricFactor: got %d want %d (in=%d)", c.GeometricFactor, wantFactor, factor)
		}
		wantRetries := 5
		if retries >= 1 {
			wantRetries = retries
		}
		if c.PushRetries != wantRetries {
			t.Fatalf("PushRetries: got %d want %d (in=%d)", c.PushRetries, wantRetries, retries)
		}
	})
}

// clean reports whether s can round-trip as a single `key value` field: it has
// no surrounding whitespace and no embedded newline/carriage return that would
// split or reframe the config line.
func clean(s string) bool {
	return s == strings.TrimSpace(s) && !strings.ContainsAny(s, "\n\r")
}
