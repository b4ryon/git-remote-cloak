// Fuzz coverage for logx's level parser. ParseLevel maps an operator/config
// string - CLOAK_LOG env over the cloak.logLevel git-config value (the latter
// stored verbatim by the already-fuzzed config.applyConfigLines, iter 19) - to
// an slog level, falling back to a caller-supplied default. It is the pure
// downstream consumer FuzzApplyConfigLines never exercises: that target only
// asserts the raw value is stored into cfg.LogLevel, not how it is later parsed
// into a level. This is the logx package's first fuzz coverage.
package logx

import (
	"log/slog"
	"strings"
	"testing"
)

// fuzzDefault maps a selector byte to the default level passed to ParseLevel.
// It includes out-of-band sentinel levels so the fail-closed "return def" path
// is checked against a level ParseLevel can never synthesize on its own - this
// catches a regression that returns a hardcoded LevelInfo instead of honoring
// the caller's default.
func fuzzDefault(sel uint8) slog.Level {
	defs := []slog.Level{
		slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError,
		slog.Level(42), slog.Level(-128),
	}
	return defs[int(sel)%len(defs)]
}

func FuzzParseLevel(f *testing.F) {
	seeds := []string{
		"error", "warn", "warning", "info", "debug",
		"ERROR", "Warn", "WARNING", "Info", "DEBUG",
		" debug ", "\tinfo\n", "", "   ", "bogus", "warn ",
		"err", "informational", "warnwarn", "débug", "\x00", "info\x00",
	}
	for _, s := range seeds {
		for _, sel := range []uint8{0, 2, 4, 5} {
			f.Add(s, sel)
		}
	}

	// expected is the independent ground-truth mapping. Only the normalization
	// (trim+lower) is shared with the implementation; these target levels are
	// hardcoded here so a swapped, dropped, or relabeled case (e.g. "warn"
	// mapped to LevelError, or "warning" dropped) is caught rather than mirrored.
	expected := map[string]slog.Level{
		"error":   slog.LevelError,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"info":    slog.LevelInfo,
		"debug":   slog.LevelDebug,
	}

	f.Fuzz(func(t *testing.T, s string, sel uint8) {
		def := fuzzDefault(sel)
		got := ParseLevel(s, def)

		// Membership: the result is always one of the four named levels or the
		// caller's default - never some other arbitrary level.
		switch got {
		case slog.LevelError, slog.LevelWarn, slog.LevelInfo, slog.LevelDebug, def:
		default:
			t.Fatalf("ParseLevel(%q, %v) = %v: not a named level nor the default", s, def, got)
		}

		// Determinism: a pure parse must return the same level on re-read.
		if again := ParseLevel(s, def); again != got {
			t.Fatalf("ParseLevel(%q, %v) nondeterministic: %v then %v", s, def, got, again)
		}

		// Exact contract: a recognized token maps to its fixed level; everything
		// else (including empty and all-whitespace) fails closed to the default.
		norm := strings.ToLower(strings.TrimSpace(s))
		if want, ok := expected[norm]; ok {
			if got != want {
				t.Fatalf("ParseLevel(%q, %v) = %v, want %v for recognized %q", s, def, got, want, norm)
			}
		} else if got != def {
			t.Fatalf("ParseLevel(%q, %v) = %v, want default %v for unrecognized %q", s, def, got, def, norm)
		}

		// Whitespace tolerance: ParseLevel trims surrounding whitespace, and
		// TrimSpace(ws+s+ws) == TrimSpace(s) for any whitespace ws and any s,
		// so wrapping the input in arbitrary surrounding ASCII whitespace can
		// never change the result. This pins the trim as an observable invariant
		// independently of the normalization restated above.
		if wrapped := ParseLevel(" \t\r\n"+s+"\n\r\t ", def); wrapped != got {
			t.Fatalf("ParseLevel surrounding-whitespace sensitive: bare=%v wrapped=%v for %q", got, wrapped, s)
		}
	})
}
