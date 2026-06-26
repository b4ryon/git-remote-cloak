// Fuzz tests for the side-effect-free protocol layer: the parsers that consume
// untrusted input from git before any session or remote work (collectBatch for
// multi-line fetch/push batches, parseRefUpdate, option, the integrated Main
// dispatch loop) and the formatters that frame the helper's responses back onto
// git's stream (the list advertisement, pushReportLines for the push status
// report, and fetchLockLines for the fetch lock report). Whatever git -- or a
// confused caller -- sends, the parsers must never panic and must always
// terminate, and the formatters must emit exactly one well-framed protocol line
// per item so git attributes each outcome to the right ref or lock. The "option"
// command additionally carries a state-mutation contract (it sets s.forceAll,
// s.dryRun, and s.verbosity, which gate downstream push authorization): FuzzOption
// pins its reply and FuzzOptionState pins those side effects. These targets are
// deliberately scoped to the layer that needs no repository: the list/fetch/push
// handlers reach the filesystem via setup.Open and are exercised by the
// integration tests.
//
// FuzzMainStreamFailsClosed pins one more side-effect-free contract of the
// integrated Main that FuzzDispatchSession deliberately avoids: the protocol
// stream reader's fail-closed behavior when git sends a line that exceeds Main's
// 1 MiB scanner buffer. FuzzDispatchSession bounds its option value precisely so
// it never trips that scanner error (its byte-exact replay oracle cannot model a
// mid-stream read failure); this target drives the boundary directly with a
// single oversized line and asserts Main fails closed (exit 1, nothing on
// stdout) rather than silently treating an unreadable stream as a clean session.
package helper

import (
	"bufio"
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/engine"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

// newProtocolScanner mirrors the line scanner Main builds for the protocol
// stream (bufio.ScanLines splitting plus the same large line buffer), so a test
// scanner enumerates lines exactly as the production one collectBatch consumes.
func newProtocolScanner(s string) *bufio.Scanner {
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	return sc
}

// scanLines returns every line of s as the protocol scanner would split it.
// collectBatch can only read lines through this same scanner, so this is the
// ground truth for which lines exist; the oracle below re-derives collectBatch's
// break/prefix/strip DECISIONS over these lines independently.
func scanLines(s string) []string {
	sc := newProtocolScanner(s)
	var out []string
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// FuzzCollectBatch pins collectBatch, the fetch/push batch reader, against an
// independent oracle. collectBatch reads a contiguous run of prefix-carrying
// lines from the protocol scanner until a blank line or EOF, strips the prefix
// from each, and -- crucially for the dispatch loop -- consumes the terminating
// blank so Main's `for in.Scan()` resumes at the NEXT command (helper.go). The
// full contract therefore has four parts the old no-panic check left unpinned:
// item faithfulness (each batch line, prefix-stripped, in order), batch framing
// (the first blank ends the batch and is not an item), error-on-bad-prefix (a
// non-blank line lacking the prefix is rejected), and scanner positioning (after
// a clean batch the scanner yields exactly the lines following the blank).
func FuzzCollectBatch(f *testing.F) {
	f.Add("fetch aaaa refs/heads/main\nfetch bbbb refs/heads/dev\n")
	f.Add("push refs/heads/main:refs/heads/main\n+push x:y\n")
	f.Add("fetch x\nWAT\n")
	f.Add("fetch a\n\nfetch b\n") // blank ends the batch; "fetch b" must remain
	f.Add("fetch a\nfetch b")     // no blank: EOF ends the batch, nothing remains
	f.Add("fetch \nfetch x\n")    // a line that is exactly the prefix is an empty item
	f.Add("fetch a\n\n")          // trailing blank consumed, nothing remains
	f.Add("")

	f.Fuzz(func(t *testing.T, stream string) {
		for _, prefix := range []string{"fetch ", "push "} {
			lines := scanLines(stream)
			if len(lines) == 0 || !strings.HasPrefix(lines[0], prefix) {
				continue // collectBatch's precondition: a prefixed opening line
			}

			// Independently re-derive the expected items, the index where the
			// remaining stream begins, and whether a bad-prefix line forces an
			// error -- mirroring collectBatch's loop without calling it.
			wantItems := []string{strings.TrimPrefix(lines[0], prefix)}
			wantErr := false
			batchEnd := len(lines) // exclusive index where the remainder starts
			for j := 1; j < len(lines); j++ {
				if lines[j] == "" {
					batchEnd = j + 1 // the terminating blank is consumed
					break
				}
				if !strings.HasPrefix(lines[j], prefix) {
					wantErr = true
					break
				}
				wantItems = append(wantItems, strings.TrimPrefix(lines[j], prefix))
			}

			// Run collectBatch positioned exactly as the dispatch loop leaves it:
			// the opener already pulled off by Main's in.Scan() and handed in.
			sc := newProtocolScanner(stream)
			sc.Scan()
			items, err := collectBatch(sc, sc.Text(), prefix)

			if wantErr {
				if err == nil {
					t.Fatalf("collectBatch(%q, prefix=%q) accepted a batch carrying a non-%q line", stream, prefix, prefix)
				}
				continue // on rejection the scanner position is unspecified
			}
			if err != nil {
				t.Fatalf("collectBatch(%q, prefix=%q) rejected a well-formed batch: %v", stream, prefix, err)
			}
			if !slices.Equal(items, wantItems) {
				t.Fatalf("collectBatch(%q, prefix=%q) items = %q, want %q", stream, prefix, items, wantItems)
			}
			// Scanner-positioning contract: draining what collectBatch left must
			// yield exactly the lines after the (consumed) terminating blank, so
			// the dispatch loop resumes on the next command rather than dropping
			// or re-reading one.
			var rest []string
			for sc.Scan() {
				rest = append(rest, sc.Text())
			}
			if !slices.Equal(rest, lines[batchEnd:]) {
				t.Fatalf("collectBatch(%q, prefix=%q) left %q after the batch, want %q", stream, prefix, rest, lines[batchEnd:])
			}
		}
	})
}

func FuzzParseRefUpdate(f *testing.F) {
	f.Add("refs/heads/main:refs/heads/main", false)
	f.Add("+refs/heads/main:refs/heads/main", false)
	f.Add(":refs/heads/main", true) // delete request
	f.Add("src:dst", false)
	f.Add("a:b:c", false) // src keeps everything before the first colon
	f.Add("+", false)
	f.Add("", false)

	f.Fuzz(func(t *testing.T, spec string, forceAll bool) {
		u, err := parseRefUpdate(spec, forceAll)
		if err != nil {
			return // a rejected refspec is fine; the requirement is no panic
		}
		// An accepted update always names a destination ref.
		if u.Dst == "" {
			t.Fatalf("parseRefUpdate(%q, %v) accepted an empty destination", spec, forceAll)
		}
		// Force holds exactly when the caller forced everything or the spec
		// carried the explicit leading "+"; nothing else may flip it.
		wantForce := forceAll || strings.HasPrefix(spec, "+")
		if u.Force != wantForce {
			t.Fatalf("parseRefUpdate(%q, %v) Force = %v, want %v", spec, forceAll, u.Force, wantForce)
		}
	})
}

// FuzzListAdvertisementFraming pins the protocol-framing safety of the ref
// advertisement the helper emits from the manifest. list formats each ref as a
// single "<oid> <name>" line and the head as "@<head> HEAD" (helper.go), and
// git reads that advertisement one line at a time. The manifest is the
// advertisement's root of trust, so a ref name or head it accepts must never
// contain a byte that splits or corrupts a protocol line: a newline would inject
// a forged advertisement line (e.g. a second ref pointing wherever the attacker
// chose), feeding git a ref it never published.
//
// Only manifests that Validate accepts reach list in production (the remote
// state is built by Decode, which validates), so the fuzzer builds a manifest
// from a fuzzed ref name, validates it, and -- for any manifest that passes --
// drives the real list path and asserts every emitted line is a single protocol
// line. This exercises the manifest gate through its actual protocol consumer
// rather than re-asserting the gate's predicate.
func FuzzListAdvertisementFraming(f *testing.F) {
	const (
		repoID = "0123456789abcdef0123456789abcdef"
		oid    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	f.Add("refs/heads/main", true)
	f.Add("refs/heads/main\n0000000000000000000000000000000000000000 refs/heads/evil", true) // injection attempt
	f.Add("refs/heads/x\ty", false)
	f.Add("refs/tags/v1", false)
	f.Add("refs/heads/space here", true)

	f.Fuzz(func(t *testing.T, refName string, asHead bool) {
		m := &manifest.Manifest{
			Version: manifest.Version,
			RepoID:  repoID,
			Refs:    map[string]string{refName: oid},
		}
		if asHead {
			m.Head = refName
		}
		// Production only ever advertises a manifest Decode/Validate accepted.
		if err := m.Validate(); err != nil {
			return
		}
		s := &session{ready: true, rs: &engine.RemoteState{Manifest: m}}
		for _, forPush := range []bool{false, true} {
			lines, err := s.list(forPush)
			if err != nil {
				t.Fatalf("list(forPush=%v) failed on a validated manifest: %v", forPush, err)
			}
			for _, l := range lines {
				if strings.ContainsAny(l, "\n\r") {
					t.Fatalf("list(forPush=%v) emitted advertisement line %q with an embedded newline: "+
						"a validated manifest injected an extra line into git's protocol stream", forPush, l)
				}
			}
		}
	})
}

// assertEmptyRemoteAdvertises pins list's empty-remote contract: a nil-Manifest
// RemoteState must advertise zero lines for both list and list-for-push, so git
// sees only Main's terminating blank and treats the remote as empty.
func assertEmptyRemoteAdvertises(t *testing.T, s *session) {
	t.Helper()
	for _, forPush := range []bool{false, true} {
		lines, err := s.list(forPush)
		if err != nil {
			t.Fatalf("list(forPush=%v) on empty remote failed: %v", forPush, err)
		}
		if len(lines) != 0 {
			t.Fatalf("list(forPush=%v) on empty remote advertised %d lines, want 0: %q", forPush, len(lines), lines)
		}
	}
}

// parseAdvertisement decodes a ref advertisement back into its ref->oid map while
// pinning the per-line framing invariants: no embedded newline, the optional
// "@<head> HEAD" line is detected and counted (and no ref line may follow it),
// each ref line splits cleanly on its single space, no ref is advertised twice,
// and ref lines ascend by name. It returns the recovered map and the number of
// HEAD lines seen for the caller's HEAD-presence check.
func parseAdvertisement(t *testing.T, lines []string, forPush bool) (map[string]string, int) {
	t.Helper()
	parsed := map[string]string{}
	prevName := ""
	seenHead := false
	headLines := 0
	for _, l := range lines {
		if strings.ContainsAny(l, "\n\r") {
			t.Fatalf("list(forPush=%v) line %q carries an embedded newline", forPush, l)
		}
		if strings.HasPrefix(l, "@") {
			seenHead = true
			headLines++
			continue
		}
		if seenHead {
			t.Fatalf("list(forPush=%v) emitted ref line %q after the HEAD line", forPush, l)
		}
		oid, name, ok := strings.Cut(l, " ")
		if !ok {
			t.Fatalf("list(forPush=%v) ref line %q has no space", forPush, l)
		}
		if _, dup := parsed[name]; dup {
			t.Fatalf("list(forPush=%v) advertised ref %q twice", forPush, name)
		}
		if prevName != "" && name <= prevName {
			t.Fatalf("list(forPush=%v) ref lines not ascending: %q after %q", forPush, name, prevName)
		}
		parsed[name] = oid
		prevName = name
	}
	return parsed, headLines
}

// assertAdvertisementHead pins the post-parse half of list's contract: the ref
// lines recover exactly the manifest's refs, and the "@<head> HEAD" symref line
// is present exactly once and last iff this is a non-for-push list with a
// non-empty HeadForList selection.
func assertAdvertisementHead(t *testing.T, lines []string, m *manifest.Manifest, forPush bool, parsed map[string]string, headLines int) {
	t.Helper()
	// Faithful: the ref lines are exactly the manifest's refs.
	if !maps.Equal(parsed, m.Refs) {
		t.Fatalf("list(forPush=%v) advertised refs %v != manifest refs %v", forPush, parsed, m.Refs)
	}
	// The HEAD symref line is present exactly once and last iff this is a
	// non-for-push list with a non-empty HeadForList selection.
	wantHead := ""
	if !forPush {
		wantHead = engine.HeadForList(m)
	}
	if wantHead == "" {
		if headLines != 0 {
			t.Fatalf("list(forPush=%v) emitted %d HEAD lines, want 0", forPush, headLines)
		}
		return
	}
	if headLines != 1 {
		t.Fatalf("list(forPush=%v) emitted %d HEAD lines, want 1", forPush, headLines)
	}
	if want := "@" + wantHead + " HEAD"; lines[len(lines)-1] != want {
		t.Fatalf("list(forPush=%v) HEAD line = %q, want %q", forPush, lines[len(lines)-1], want)
	}
}

// FuzzListAdvertisement pins the multi-ref faithfulness, ordering, and HEAD
// framing of the ref advertisement the helper emits from a validated manifest.
// Where FuzzListAdvertisementFraming drives a single ref to prove no line
// carries an injecting newline, this drives an arbitrary ref SET through the
// real list path (helper.go) and asserts the whole advertisement is a lossless,
// well-ordered, one-line-per-ref encoding of the manifest's refs: parsing every
// "<oid> <name>" line back recovers exactly the manifest's ref->oid map (none
// dropped, duplicated, or invented), the ref lines are emitted in ascending
// name order, and the optional "@<head> HEAD" symref line appears last and only
// for a non-for-push list whose HeadForList selection is non-empty (delegating
// the selection's own correctness to HeadForList/FuzzHeadForList).
//
// Disambiguation is airtight: a ref oid is 40 hex chars and a ref name starts
// with "refs/", so only the HEAD line ever begins with '@', and a validated ref
// name carries no space, so each ref line splits cleanly on its single space.
// Only manifests Validate accepts reach list in production, so the fuzzer keeps
// just those.
//
// The emptyRemote dimension pins the other half of list's contract that every
// non-empty oracle above leaves untouched: when the remote has no backend
// branch yet, LoadRemoteState returns a RemoteState with a nil Manifest
// (engine.go: "Manifest is ... nil when empty"), and list must then advertise
// NOTHING -- zero ref lines and zero "@<head> HEAD" line for both list and
// list-for-push -- so git sees only Main's terminating blank and treats the
// remote as empty (a fresh clone yields an empty repo, the first push seeds it).
// A bug that invented a ref or HEAD line for an empty remote would corrupt that
// handshake; this branch was reachable but had no unit or fuzz coverage, so the
// nil-manifest seed gives it deterministic regression protection under go test.
func FuzzListAdvertisement(f *testing.F) {
	const repoID = "0123456789abcdef0123456789abcdef"
	f.Add(false, "refs/heads/main\nrefs/heads/dev", "")
	f.Add(false, "refs/heads/z\nrefs/heads/a\nrefs/heads/m", "")
	f.Add(false, "refs/tags/v1\nrefs/heads/master\nrefs/heads/main", "refs/heads/master")
	f.Add(false, "refs/heads/dup\nrefs/heads/dup", "refs/heads/dup")
	f.Add(false, "refs/tags/only", "")
	f.Add(false, "", "")
	f.Add(true, "refs/heads/main", "refs/heads/main") // empty remote: refs/head ignored

	f.Fuzz(func(t *testing.T, emptyRemote bool, refsBlob, head string) {
		// Empty remote: nil Manifest must advertise nothing, regardless of any
		// (ignored) head/refs the fuzzer supplies, for both list and for-push.
		if emptyRemote {
			assertEmptyRemoteAdvertises(t, &session{ready: true, rs: &engine.RemoteState{}})
			return
		}

		m := &manifest.Manifest{
			Version: manifest.Version,
			RepoID:  repoID,
			Head:    head,
			Refs:    map[string]string{},
		}
		for i, name := range strings.Split(refsBlob, "\n") {
			if name != "" {
				// A distinct valid 40-hex oid per ref makes the parse-back a true
				// bijection check: a swapped or relabeled oid would be caught.
				m.Refs[name] = fmt.Sprintf("%040x", i)
			}
		}
		// list only ever sees a manifest Decode/Validate accepted.
		if err := m.Validate(); err != nil {
			return
		}
		s := &session{ready: true, rs: &engine.RemoteState{Manifest: m}}

		for _, forPush := range []bool{false, true} {
			lines, err := s.list(forPush)
			if err != nil {
				t.Fatalf("list(forPush=%v) failed on a validated manifest: %v", forPush, err)
			}
			parsed, headLines := parseAdvertisement(t, lines, forPush)
			assertAdvertisementHead(t, lines, m, forPush, parsed, headLines)
		}
	})
}

func FuzzOption(f *testing.F) {
	f.Add("verbosity 2")
	f.Add("dry-run true")
	f.Add("force false")
	f.Add("progress true")
	f.Add("depth 5")
	f.Add("")

	f.Fuzz(func(t *testing.T, rest string) {
		s := &session{}
		reply := s.option(rest)
		// The protocol allows exactly these two answers for an option line.
		if reply != "ok" && reply != "unsupported" {
			t.Fatalf("option(%q) = %q, want \"ok\" or \"unsupported\"", rest, reply)
		}
	})
}

// assertOptionReply pins the reply classification: "ok" for the four known
// options (verbosity/progress/dry-run/force), "unsupported" for anything else.
func assertOptionReply(t *testing.T, rest, name, reply string) {
	t.Helper()
	known := name == "verbosity" || name == "progress" || name == "dry-run" || name == "force"
	wantReply := "unsupported"
	if known {
		wantReply = "ok"
	}
	if reply != wantReply {
		t.Fatalf("option(%q) reply = %q, want %q", rest, reply, wantReply)
	}
}

// assertOptionState pins option's state-mutation contract against the
// independently-split name/value: forceAll and dryRun flip only for their own
// option name and only on the exact value "true"; verbosity is untouched by any
// non-"verbosity" option; and on the clean decimal-integer domain "verbosity <n>"
// sets verbosity to n. The session arrives pre-seeded with the non-default
// sentinels (forceAll/dryRun true, verbosity initVerb) so a spurious write shows.
func assertOptionState(t *testing.T, rest, name, value string, s *session, initVerb int) {
	t.Helper()
	// Boolean exact-"true" semantics + isolation: forceAll/dryRun change only
	// for their own option name, and only to value=="true".
	wantForce := true // initial sentinel
	if name == "force" {
		wantForce = value == "true"
	}
	if s.forceAll != wantForce {
		t.Fatalf("option(%q): forceAll = %v, want %v", rest, s.forceAll, wantForce)
	}
	wantDry := true // initial sentinel
	if name == "dry-run" {
		wantDry = value == "true"
	}
	if s.dryRun != wantDry {
		t.Fatalf("option(%q): dryRun = %v, want %v", rest, s.dryRun, wantDry)
	}

	// verbosity isolation: no non-"verbosity" option may touch it.
	if name != "verbosity" && s.verbosity != initVerb {
		t.Fatalf("option(%q): verbosity changed to %d by a non-verbosity option", rest, s.verbosity)
	}
	// On the clean decimal-integer domain, "verbosity <n>" sets verbosity to n.
	if name == "verbosity" {
		if n, err := strconv.Atoi(value); err == nil && s.verbosity != n {
			t.Fatalf("option(%q): verbosity = %d, want %d", rest, s.verbosity, n)
		}
	}
}

// FuzzOptionState fuzzes the STATE-MUTATION contract of the "option" command --
// the load-bearing half that FuzzOption (reply only) and FuzzDispatchSession
// (stdout only) never check. option mutates s.forceAll, s.dryRun, and
// s.verbosity, and those flags gate real push behavior downstream: s.forceAll is
// passed to parseRefUpdate to force every ref update (the non-fast-forward
// authorization), s.dryRun is passed to engine.Push to make a push a no-op
// simulation, and s.verbosity drives logging. A bug that flipped forceAll as a
// side effect of an unrelated option, or honored a value other than the exact
// "true", would silently change push authorization without affecting the reply
// the existing fuzzers assert on -- so this pins:
//   - isolation: each option mutates only its own field (verbosity is never
//     changed by a non-"verbosity" option; each boolean only by its own name),
//   - the exact-"true" boolean semantics: force/dry-run flip true IFF the value
//     after the first space is exactly "true" (so "TRUE", "1", "true x", and a
//     trailing-space "true " all leave the flag false),
//   - the reply classification (ok for the four known options, unsupported else),
//   - and, on the clean decimal-integer domain, that "verbosity <n>" sets
//     verbosity to n.
//
// The name/value split is re-derived via strings.IndexByte (a distinct
// decomposition of the production strings.Cut on a single-byte separator) so the
// state oracle is non-circular. The verbosity value is asserted only when
// strconv.Atoi accepts it: for every Atoi-accepted value fmt.Sscanf("%d")
// produces the identical int (verified empirically), while the cases where they
// diverge -- leading whitespace, trailing garbage, "0x"-forms, overflow -- all
// make Atoi return a non-nil error and are skipped, so there is no false positive.
func FuzzOptionState(f *testing.F) {
	f.Add("force true")
	f.Add("force false")
	f.Add("force TRUE")   // case-sensitive: not "true", flag stays false
	f.Add("force true x") // value is "true x", not "true": flag stays false
	f.Add("force true ")  // trailing space: value "true " != "true"
	f.Add("force")        // no value: "" != "true"
	f.Add("dry-run true")
	f.Add("dry-run 1") // not "true": flag stays false
	f.Add("verbosity 2")
	f.Add("verbosity -3")
	f.Add("verbosity 007")
	f.Add("verbosity notanint") // parse fails, verbosity unchanged
	f.Add("verbosity")          // no value
	f.Add("verbosity 5 6")      // value "5 6" not a clean int: skipped
	f.Add("progress true")
	f.Add("unknownopt whatever")
	f.Add("")

	f.Fuzz(func(t *testing.T, rest string) {
		// Distinct non-default sentinels so a wrong-field write is visible: the
		// production defaults are false/false/0, so starting from true/true/<neg>
		// makes any spurious clear or set stand out.
		const initVerb = -987654321
		s := &session{verbosity: initVerb, dryRun: true, forceAll: true}
		reply := s.option(rest)

		// Independent name/value split: IndexByte on a single byte is the exact
		// decomposition of the production strings.Cut(rest, " ").
		name, value := rest, ""
		if i := strings.IndexByte(rest, ' '); i >= 0 {
			name, value = rest[:i], rest[i+1:]
		}

		assertOptionReply(t, rest, name, reply)
		assertOptionState(t, rest, name, value, s, initVerb)
	})
}

// buildDispatchScript turns an opcode stream into the protocol script fed to
// Main and, in lockstep, the exact stdout and exit code Main must produce. Main
// stops dispatching at the first blank or unknown line, so the expectation stops
// accumulating there too (terminated) while the script keeps the trailing
// never-read lines. Each option answer is computed via the real option() so the
// oracle restates neither the capabilities block nor option's reply logic.
func buildDispatchScript(ops []byte, arg string) (string, string, int) {
	ref := &session{} // computes each option answer via the real option()
	var script, want strings.Builder
	wantCode := 0
	terminated := false
	for _, op := range ops {
		switch op % 4 {
		case 0:
			script.WriteString("capabilities\n")
			if !terminated {
				for _, c := range capabilities {
					want.WriteString(c)
					want.WriteByte('\n')
				}
				want.WriteByte('\n')
			}
		case 1:
			script.WriteString("option " + arg + "\n")
			if !terminated {
				want.WriteString(ref.option(arg))
				want.WriteByte('\n')
			}
		case 2:
			script.WriteString("\n")
			if !terminated {
				terminated = true // the blank line ends the dialogue cleanly (exit 0)
			}
		case 3:
			script.WriteString("zzz-unknown\n")
			if !terminated {
				terminated = true
				wantCode = 1 // unknown command -> fatal on stderr, exit 1
			}
		}
	}
	return script.String(), want.String(), wantCode
}

// FuzzDispatchSession fuzzes the helper's top-level protocol dispatch loop --
// the Main read-dispatch-flush dialogue (helper.go) that routes git's
// line-oriented commands -- as an INTEGRATED unit, which the per-parser fuzzers
// (FuzzCollectBatch, FuzzParseRefUpdate, FuzzOption) never exercise. It drives
// the real Main over fuzz-generated multi-command sessions, but built only from
// the side-effect-free command vocabulary (capabilities, option, the blank
// terminator, and an unknown command); list/fetch/push are deliberately
// excluded because they reach the filesystem and git subprocesses via
// setup.Open (the same scoping the other helper fuzzers use). To keep the
// session confined to that vocabulary even under mutation, the fuzzed option
// value has any embedded newline stripped, so it can never smuggle in a
// list/fetch/push line.
//
// The oracle is exact: replaying the same opcode stream must reproduce Main's
// entire stdout byte-for-byte and its exit code. That pins the whole-dialogue
// contract no single-parser test covers: the dispatcher routes each command to
// the right handler, frames every response correctly (capabilities emits
// exactly the advertised list plus the terminating blank; each option answer is
// exactly one line), preserves order and count across a multi-command session,
// terminates on the blank line, fails an unknown command on stderr with exit 1,
// and -- the protocol-safety property -- never emits anything but valid protocol
// tokens onto git's stream. The expected capabilities block is derived from the
// production capabilities slice and the expected option answer from the real
// option(), so this verifies the dispatch/framing without restating either.
func FuzzDispatchSession(f *testing.F) {
	f.Add([]byte{0}, "verbosity 2")            // capabilities only, EOF-terminated
	f.Add([]byte{1}, "dry-run true")           // one accepted option
	f.Add([]byte{1}, "totally-unknown-option") // one unsupported option
	f.Add([]byte{0, 1, 1, 2}, "force false")   // caps, two options, blank terminator
	f.Add([]byte{3}, "x")                      // unknown command -> exit 1
	f.Add([]byte{0, 3}, "progress true")       // caps then unknown
	f.Add([]byte{1, 0, 1}, "verbosity bogus")  // interleaved option/caps/option
	f.Add([]byte{2, 0}, "")                    // immediate blank: nothing after it runs
	f.Add([]byte{}, "")

	f.Fuzz(func(t *testing.T, ops []byte, optArg string) {
		// A real option line is a single protocol line, so strip any embedded
		// newline/carriage-return: this matches git's framing and keeps the
		// generated script inside the safe vocabulary (a newline could otherwise
		// inject a list/fetch/push line that reaches setup.Open).
		arg := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, optArg)
		// Bound the option value so no single line exceeds Main's 1 MiB scanner
		// buffer (which would make Main fail on a scan error the replay does not
		// model); honest option values are tiny.
		if len(arg) > 4096 {
			return
		}

		// Build the protocol script and, in lockstep, the exact stdout and exit
		// code Main must produce.
		script, want, wantCode := buildDispatchScript(ops, arg)

		var out, errBuf bytes.Buffer
		code := Main([]string{"origin", "cloak::x"}, strings.NewReader(script), &out, &errBuf)

		if code != wantCode {
			t.Fatalf("Main exit code = %d, want %d (ops=%v arg=%q)", code, wantCode, ops, arg)
		}
		if got := out.String(); got != want {
			t.Fatalf("dispatch stdout mismatch (ops=%v arg=%q):\n got %q\nwant %q", ops, arg, got, want)
		}
	})
}

// FuzzMainStreamFailsClosed pins the protocol stream reader's fail-closed
// contract. Main reads git's command stream through a bufio.Scanner capped at a
// 1 MiB line buffer (in.Buffer(make([]byte, 0, 64*1024), 1<<20), helper.go); a
// protocol line longer than that cap makes Scan return false with
// in.Err()==bufio.ErrTooLong, and Main must route that through fatal -- exit
// code 1, a classified error on stderr -- rather than fall through to the clean
// "return 0" as if the dialogue ended normally. Treating an unreadable or
// truncated stream as a successful empty session is the failure this branch
// (helper.go in.Err handling) guards against, and no prior test reached it:
// FuzzDispatchSession caps its option value at 4096 bytes specifically so it
// never trips the scanner, and the unit tests use short lines.
//
// The target drives a single line of fuzzed length straddling the buffer cap and
// asserts the universal fail-closed contract: Main returns exit 1, writes
// nothing to stdout (an unreadable stream must never produce a spurious
// advertisement), and reports on stderr. The contract holds on BOTH sides of the
// cap -- a line at/over the cap fails via the scanner error (the newly covered
// branch), a shorter line is an unrecognized command (default case) -- so the
// oracle is threshold-independent and never couples to bufio's exact boundary.
//
// This stays side-effect-free without any vocabulary confinement: a line of a
// single repeated byte can never form a list/fetch/push command (those need
// distinct characters or an embedded space), so the under-cap path always lands
// in dispatchLine's default (unknown command) case and never reaches
// ensure()/setup.Open. A '\n' fill is excluded because it would split the input
// into multiple (blank) lines and terminate the dialogue early with exit 0,
// which is correct behavior but a different contract than the single-line one
// pinned here.
func FuzzMainStreamFailsClosed(f *testing.F) {
	// Mirrors Main's max scanner token size; the test does not depend on the
	// exact boundary, only that lengths straddle it.
	const scanBuf = 1 << 20

	f.Add(byte('a'), uint16(0))    // scanBuf-64: under the cap -> unknown command
	f.Add(byte('a'), uint16(127))  // scanBuf+63: over the cap -> scanner error
	f.Add(byte('a'), uint16(64))   // exactly scanBuf: the boundary -> scanner error
	f.Add(byte(0), uint16(70))     // NUL fill, over the cap
	f.Add(byte(' '), uint16(10))   // space fill, under the cap
	f.Add(byte('\r'), uint16(100)) // CR fill (no LF, so still a single line), over the cap

	f.Fuzz(func(t *testing.T, fill byte, extra uint16) {
		if fill == '\n' {
			return // a newline makes multiple lines; this target pins the single-line contract
		}
		// Length in [scanBuf-64, scanBuf+63]: straddles the buffer cap so the
		// fuzzer reaches both the scanner-error branch and the unknown-command path.
		length := scanBuf - 64 + int(extra%128)
		line := bytes.Repeat([]byte{fill}, length)

		var out, errBuf bytes.Buffer
		code := Main([]string{"origin", "cloak::x"}, bytes.NewReader(line), &out, &errBuf)

		// Fail closed: a line that exceeds the scanner buffer (or any unrecognized
		// command) must exit 1, never 0 -- a swallowed scanner error returning 0
		// would make Main treat a truncated/oversized stream as a clean session.
		if code != 1 {
			t.Fatalf("Main on a %d-byte single line (fill=%#x) returned %d, want 1 (fail closed)", length, fill, code)
		}
		// No protocol output: an unreadable stream advertises nothing.
		if out.Len() != 0 {
			t.Fatalf("Main on a %d-byte single line (fill=%#x) wrote %d stdout bytes, want 0", length, fill, out.Len())
		}
		// Fail-closed reporting: the classified error goes to stderr.
		if errBuf.Len() == 0 {
			t.Fatalf("Main on a %d-byte single line (fill=%#x) failed closed without reporting on stderr", length, fill)
		}
	})
}

// FuzzPushReportLines pins the framing of the push status report the helper
// writes back to git -- the write-side sibling of the list advertisement
// (FuzzListAdvertisement). handlePush (helper.go) formats each per-ref push
// outcome as "ok <dst>" (accepted) or "error <dst> <err>" (rejected), one line
// per result, and git reads that report a line at a time to learn each ref's
// fate. A framing slip -- a dropped or duplicated line, a swapped status word,
// or a transposed dst/err -- would make git misreport which ref actually landed.
//
// The oracle decodes each emitted line back by an independent decomposition
// (cut off the leading status word, then cut dst from err) and asserts the
// recovered (status, dst, err) reproduces the input RefResult, so it verifies
// the framing without restating the formatter's own concatenation. In
// production every dst is a ref name from a single "push" refspec line (no
// space, no embedded newline), so the "error <dst> <err>" split is unambiguous;
// the error-branch dst/err round-trip is therefore scoped to that space-free
// domain, while the line count, the status word, and determinism are pinned for
// every input.
func FuzzPushReportLines(f *testing.F) {
	f.Add("refs/heads/main", "", "refs/heads/dev", "non-fast-forward")
	f.Add("refs/heads/x", "fetch first", "refs/heads/y", "")
	f.Add("refs/tags/v1", "cannot resolve refs/tags/v1 to a commit", "", "")
	f.Add("", "", "refs/heads/z", "remote ref does not exist")
	f.Add("refs/heads/a b", "", "c d", "x y z") // spaces stress the decode

	f.Fuzz(func(t *testing.T, dst0, err0, dst1, err1 string) {
		results := []engine.RefResult{{Dst: dst0, Err: err0}, {Dst: dst1, Err: err1}}
		lines := pushReportLines(results)

		// Exactly one report line per result, preserving order.
		if len(lines) != len(results) {
			t.Fatalf("pushReportLines returned %d lines for %d results", len(lines), len(results))
		}
		for i, r := range results {
			l := lines[i]
			// The formatter always emits "ok " or "error " before the payload, so
			// a status-word separator is always present; its absence means the
			// leading space was dropped.
			word, rest, ok := strings.Cut(l, " ")
			if !ok {
				t.Fatalf("report line %q for result %+v lacks the status-word separator", l, r)
			}
			if r.Err == "" {
				// Accepted: "ok <dst>". The remainder is the whole dst (faithful
				// even when dst carries spaces, since nothing follows it).
				if word != "ok" {
					t.Fatalf("accepted result %+v reported with status %q, want \"ok\"", r, word)
				}
				if rest != r.Dst {
					t.Fatalf("ok line %q decoded dst %q, want %q", l, rest, r.Dst)
				}
				continue
			}
			// Rejected: "error <dst> <err>".
			if word != "error" {
				t.Fatalf("rejected result %+v reported with status %q, want \"error\"", r, word)
			}
			// The dst/err split is unambiguous only when dst is space-free, which
			// every production ref name is; round-trip the decode in that domain.
			if !strings.Contains(r.Dst, " ") {
				gotDst, gotErr, ok := strings.Cut(rest, " ")
				if !ok {
					t.Fatalf("error line %q lacks the dst/err separator", l)
				}
				if gotDst != r.Dst || gotErr != r.Err {
					t.Fatalf("error line %q decoded (dst=%q, err=%q), want (%q, %q)", l, gotDst, gotErr, r.Dst, r.Err)
				}
			}
		}

		// Pure function of the results: same input, same lines.
		if again := pushReportLines(results); !slices.Equal(lines, again) {
			t.Fatalf("pushReportLines not deterministic: %q vs %q", lines, again)
		}
	})
}

// FuzzFetchLockLines pins the framing of the fetch lock report the helper writes
// back to git -- the fetch-side sibling of pushReportLines (FuzzPushReportLines).
// handleFetch (helper.go) formats each kept .keep pack path as a single
// "lock <path>" line, one line per lock, and git reads that report a line at a
// time to learn which packfiles are locked for the duration of the fetch. A
// framing slip -- a dropped or duplicated line, a missing "lock" word, or a
// mangled path -- would make git lock (or fail to lock) the wrong packfile.
//
// The oracle decodes each emitted line back by an independent decomposition (cut
// off the leading "lock" word; the remainder is the whole path) and asserts the
// recovered path reproduces the input lock verbatim, so it verifies the framing
// without restating the formatter's own concatenation. In production every lock
// is a filesystem path built by keepFileFromIndexPack from the git dir plus the
// pack hash (newline-free), so the path is the entire remainder after "lock ":
// the round-trip is exact even when the path carries spaces. The line count, the
// "lock" word, and determinism are pinned for every input.
func FuzzFetchLockLines(f *testing.F) {
	f.Add(".git/objects/pack/pack-aaaa.keep", ".git/objects/pack/pack-bbbb.keep")
	f.Add("", "")
	f.Add("/abs/path with spaces/pack-c.keep", "relative.keep")
	f.Add("only-one.keep", "")
	f.Add("a\tb.keep", "weird path.keep")

	f.Fuzz(func(t *testing.T, lock0, lock1 string) {
		locks := []string{lock0, lock1}
		lines := fetchLockLines(locks)

		// Exactly one lock line per lock, preserving order.
		if len(lines) != len(locks) {
			t.Fatalf("fetchLockLines returned %d lines for %d locks", len(lines), len(locks))
		}
		for i, lk := range locks {
			l := lines[i]
			// The formatter always emits "lock " before the path, so the word
			// separator is always present; its absence means it was dropped.
			word, rest, ok := strings.Cut(l, " ")
			if !ok {
				t.Fatalf("lock line %q for lock %q lacks the word separator", l, lk)
			}
			if word != "lock" {
				t.Fatalf("lock line %q for lock %q has word %q, want \"lock\"", l, lk, word)
			}
			// The remainder is the whole path (faithful even when the path carries
			// spaces, since nothing follows it on the line).
			if rest != lk {
				t.Fatalf("lock line %q decoded path %q, want %q", l, rest, lk)
			}
		}

		// Pure function of the locks: same input, same lines.
		if again := fetchLockLines(locks); !slices.Equal(lines, again) {
			t.Fatalf("fetchLockLines not deterministic: %q vs %q", lines, again)
		}
	})
}
