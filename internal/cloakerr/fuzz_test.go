// Fuzz tests for the error taxonomy's two reporting guarantees, both of which
// carry host-influenced text into operator-visible output.
//
// Error.Error() is what a classified failure renders to: the helper and CLI
// print cloakerr.Message(err) to stderr (helper.go:142, remotecmd.go:19),
// which git relays inline to the user. The Op/Err/Hint fields routinely wrap
// host-supplied bytes (e.g. git stderr from a hostile mirror), so the wordings
// must hold over arbitrary content. Two contracts are load-bearing:
//   - The distinctive "TAMPER ALARM" / "ROLLBACK ALARM" wordings: the security
//     and integration suites grep stderr for these exact substrings to confirm
//     an attack was escalated rather than retried (test/security/forge_test.go,
//     test/integration/scenario_m{4,5}_test.go), and howto.md documents them.
//     A refactor that let a host-influenced Op/Err/Hint suppress the wording
//     would silently break that escalation.
//   - The uniform "cloak:" prefix Message guarantees on EVERY reported failure,
//     prepended exactly once and never mangling an error that already carries
//     it.
//
// The existing unit tests pin these with a handful of fixed kinds and fixed
// op/cause strings; this generalizes them over arbitrary Kind ints and
// arbitrary host-influenced text. The cloakerr package previously had zero
// fuzz coverage.
package cloakerr

import (
	"errors"
	"strings"
	"testing"
)

// FuzzClassifiedError drives the *Error reporting path over an arbitrary Kind
// int plus host-influenced Op/Err/Hint, pinning the universal "cloak:" prefix,
// the Message-is-idempotent-on-a-cloak-error faithfulness contract, the
// Tamper/Rollback distinctive-wording escalation contract, and that the
// classification and host context survive into the rendered message.
func FuzzClassifiedError(f *testing.F) {
	f.Add(int(Tamper), "decrypt manifest", "boom", true, "check your key")
	f.Add(int(Rollback), "fetch", "gen 41 < 42", true, "")
	f.Add(int(Auth), "push", "denied", true, "run cloak key import")
	f.Add(int(Network), "", "", false, "")
	f.Add(int(Protocol), "decode", "bad version", true, "")
	f.Add(99, "op", "cause", true, "hint")                     // out-of-range kind
	f.Add(-1, "op", "cause", true, "hint")                     // negative kind
	f.Add(int(Tamper), "TAMPER ALARM", "", false, "")          // host echoes the wording
	f.Add(int(Network), "a\nb", "c\nd", true, "e\nf")          // embedded newlines
	f.Add(int(Tamper), "", "cloak: network failure", true, "") // err is itself prefixed

	f.Fuzz(func(t *testing.T, kindInt int, op, errText string, hasErr bool, hint string) {
		kind := Kind(kindInt)
		var cause error
		if hasErr {
			cause = errors.New(errText)
		}
		e := &Error{Kind: kind, Op: op, Err: cause, Hint: hint}

		msg := e.Error()

		// Determinism: a pure render of the struct fields.
		if again := e.Error(); again != msg {
			t.Fatalf("Error() not deterministic: %q vs %q", msg, again)
		}

		// Universal prefix: every classified error, for any Kind including
		// out-of-range, begins with "cloak:" (in-range kinds via kindInfo, the
		// out-of-range fallback via the literal "cloak: error").
		if !strings.HasPrefix(msg, "cloak:") {
			t.Fatalf("Error() lost the cloak prefix: %q", msg)
		}

		// Message must not re-prefix a cloak error: it already starts with
		// "cloak:", so Message is a no-op on it. This is what the helper/CLI
		// rely on when they print Message(err) for a classified failure.
		if got := Message(e); got != msg {
			t.Fatalf("Message mangled a cloak error:\n got %q\nwant %q", got, msg)
		}

		// The escalation contract: the distinctive alarm wording survives into
		// operator-visible output no matter what host-influenced text the
		// Op/Err/Hint carry. Asserted on Message (the real production consumer)
		// against the literal substrings the security suite greps for.
		switch kind {
		case Tamper:
			if !strings.Contains(Message(e), "TAMPER ALARM") {
				t.Fatalf("Tamper error dropped the alarm wording: %q", msg)
			}
		case Rollback:
			if !strings.Contains(Message(e), "ROLLBACK ALARM") {
				t.Fatalf("Rollback error dropped the alarm wording: %q", msg)
			}
		}

		// Classification survives the wrapping: KindOf returns the set Kind for
		// any value (it does not range-validate), so backend.go's retry gate
		// sees exactly the kind that was assigned.
		if k, ok := KindOf(e); !ok || k != kind {
			t.Fatalf("KindOf(e) = (%v, %v), want (%v, true)", k, ok, kind)
		}

		// Host context faithfulness: non-empty Op/Err/Hint each appear verbatim
		// in the message (appended, never truncated or escaped), so a hostile
		// host cannot make cloak silently swallow the failure detail.
		if op != "" && !strings.Contains(msg, op) {
			t.Fatalf("Op not present in message: op=%q msg=%q", op, msg)
		}
		if hasErr && errText != "" && !strings.Contains(msg, errText) {
			t.Fatalf("Err text not present in message: err=%q msg=%q", errText, msg)
		}
		// The hint is appended last, so when present it is exactly the message
		// suffix. A Contains check would false-positive when host-influenced
		// Op/Err text happens to embed the "\n  hint: " sequence; HasSuffix
		// pins the real structural contract instead.
		if hint != "" && !strings.HasSuffix(msg, "\n  hint: "+hint) {
			t.Fatalf("Hint line missing or malformed: hint=%q msg=%q", hint, msg)
		}
	})
}

// FuzzMessagePrefix drives Message over arbitrary plain-error text (the
// host-influenced bytes that reach the user's terminal), pinning that the
// uniform "cloak:" prefix is added exactly once: prepended when absent, a
// no-op when already present, and idempotent under re-application.
func FuzzMessagePrefix(f *testing.F) {
	f.Add("repository not found")
	f.Add("cloak: already prefixed")
	f.Add("")
	f.Add("cloak:")
	f.Add("Cloak: wrong case")
	f.Add("  cloak: leading space")
	f.Add("line one\nline two")
	f.Add("cloak: TAMPER ALARM (forged by host)")

	f.Fuzz(func(t *testing.T, errText string) {
		got := Message(errors.New(errText))

		// Universal prefix on every reported failure.
		if !strings.HasPrefix(got, "cloak:") {
			t.Fatalf("Message did not enforce the cloak prefix: %q", got)
		}

		// Exact single-prepend gate: untouched if already prefixed, otherwise
		// prefixed exactly once.
		var want string
		if strings.HasPrefix(errText, "cloak:") {
			want = errText
		} else {
			want = "cloak: " + errText
		}
		if got != want {
			t.Fatalf("Message(%q) = %q, want %q", errText, got, want)
		}

		// Idempotence: applying Message to its own output changes nothing,
		// since the output always begins with "cloak:".
		if again := Message(errors.New(got)); again != got {
			t.Fatalf("Message not idempotent: %q -> %q", got, again)
		}
	})
}
