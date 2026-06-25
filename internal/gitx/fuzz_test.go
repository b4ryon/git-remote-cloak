// Fuzz tests for StripServerSideband, the security guard that removes
// untrusted server-relayed ("remote:"-prefixed) sideband lines from captured
// git stderr before transport-error classification. backend.classifyBlobRead
// depends on this to stop a withholding host from injecting a benign-looking
// pattern (e.g. "connection reset") that would otherwise downgrade a genuine
// missing-content Tamper into a retryable Network error. Two targets: the pure
// structural strip contract, and the end-to-end "a host cannot change the
// post-strip transport classification" security property via ClassifyTransport.
//
// A third target, FuzzParseTimeout, covers parseTimeout, the CLOAK_GIT_TIMEOUT
// parser behind every git invocation's deadline: resolveContext only arms a
// timeout when defaultTimeout() > 0, so the deadline that stops a stalled host
// from hanging the helper (and a stall being misread as tamper) hinges on this
// parser never returning a negative value and never silently disabling the
// deadline for anything but the explicit "0"/"off" opt-out tokens.
//
// A fourth target, FuzzClassifyExit, covers classifyExit, the SOURCE of the
// transport-vs-tamper taxonomy: it maps a finished git invocation to its typed
// error (nil / *TimeoutError / *CanceledError / generic / *GitError) that
// ClassifyTransport and the backend blob/fetch classifiers then consume. Its
// load-bearing security contract is the precedence of a deadline/cancel over
// the process exit code - a stalled host whose git is killed exits non-zero
// with attacker-influenced stderr, so the timeout/cancel branch MUST win and
// surface a *TimeoutError/*CanceledError (which ClassifyTransport maps to
// Network) rather than a *GitError whose stderr the regex table could read;
// that is exactly how "a stall is never tamper" holds end to end.
//
// A fifth target, FuzzApplyGitEnv, covers applyGitEnv, the pure core of
// buildEnv (every git invocation's environment). Its load-bearing security
// contract is GIT_DIR isolation: it drops every GIT_DIR= entry inherited from
// cloak's own environment so a stray parent GIT_DIR can never silently redirect
// the git subprocess to the wrong object store, and re-sets GIT_DIR only from
// the explicit o.GitDir/o.Env the caller chose. Extracted from buildEnv
// (behavior-preserving) so the parent environment is fuzz-controllable without
// mutating the process environment.
package gitx

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

// stripSeeds exercise blank input, pure-sideband stderr, mixed client/host
// lines, indented sideband, and near-miss prefixes that must be kept.
var stripSeeds = []string{
	"",
	"\n",
	"remote: connection reset",
	"fatal: unable to read blob",
	"remote: could not resolve host\nfatal: missing object 0000",
	"remote:\nremote: authentication failed\nssh: connect refused",
	"\tremote: early eof",
	"  remote: repository not found",
	"not-remote: kept\nremoteX kept\nx remote: kept",
	"remote: a\nremote: b\nremote: c",
}

func FuzzStripServerSideband(f *testing.F) {
	for _, s := range stripSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, stderr string) {
		out := StripServerSideband(stderr)

		// Every surviving line must NOT be a server "remote:" sideband line:
		// removing exactly those lines is the whole point of the guard.
		for _, ln := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(ln), "remote:") {
				t.Fatalf("server sideband line survived stripping: %q\ninput:  %q\noutput: %q", ln, stderr, out)
			}
		}

		// Stripping only deletes lines; it must never fabricate content, so
		// every surviving line must be a line of the input. (The lone empty
		// line Join yields when every line is stripped is the one exception.)
		inLines := make(map[string]bool)
		for _, ln := range strings.Split(stderr, "\n") {
			inLines[ln] = true
		}
		for _, ln := range strings.Split(out, "\n") {
			if ln == "" {
				continue
			}
			if !inLines[ln] {
				t.Fatalf("fabricated output line not present in input: %q\ninput:  %q\noutput: %q", ln, stderr, out)
			}
		}

		// Stripping is idempotent: the result has no sideband left to remove.
		if again := StripServerSideband(out); again != out {
			t.Fatalf("not idempotent:\nonce:  %q\ntwice: %q", out, again)
		}
	})
}

func FuzzSidebandInjectionCannotDowngrade(f *testing.F) {
	// Each seed pairs genuine client-origin stderr (base) with the host
	// sideband payload it would try to smuggle in; the payloads are the exact
	// fragments ClassifyTransport maps out of the conservative LocalGit default.
	seeds := []struct{ base, payload string }{
		{"", "connection reset"},
		{"fatal: unable to read blob 0000", "could not resolve host github.com"},
		{"ssh: connect to host: Connection refused", "repository 'x' not found"},
		{"remote: a\nfatal: local error", "Authentication failed\nearly EOF"},
		{"could not resolve host already", "repository not found"},
		{"network is unreachable", ""},
	}
	for _, s := range seeds {
		f.Add(s.base, s.payload)
	}
	f.Fuzz(func(t *testing.T, base, payload string) {
		// git relays each line of a server sideband message with a "remote:"
		// prefix; model that faithfully so every injected line is sideband.
		var relayed strings.Builder
		for i, ln := range strings.Split(payload, "\n") {
			if i > 0 {
				relayed.WriteByte('\n')
			}
			relayed.WriteString("remote: ")
			relayed.WriteString(ln)
		}

		want := classifyKind(StripServerSideband(base))

		// Injecting the relayed sideband before or after the genuine
		// client-origin stderr must not change the classification: a host has
		// zero influence on the post-strip taxonomy, so it can never downgrade
		// a withheld blob's Tamper into a retryable Network/Auth/RepoNotFound.
		for _, combined := range []string{
			relayed.String() + "\n" + base,
			base + "\n" + relayed.String(),
		} {
			got := classifyKind(StripServerSideband(combined))
			if got != want {
				t.Fatalf("sideband injection changed classification: want %v got %v\nbase:    %q\npayload: %q", want, got, base, payload)
			}
		}
	})
}

// timeoutSeeds exercise unset/blank, the explicit opt-out tokens (with case
// and surrounding-space variants), honored durations, zero-valued and negative
// durations that must fall back rather than disable the deadline, and garbage.
var timeoutSeeds = []string{
	"", " ", "\t\n ",
	"0", "off", "OFF", "Off", " off ", "\t0\t",
	"30s", "5m", "1h30m", "120s", "500ms", "+30s",
	"0s", "0ms", "+0", "-0", "0h0m0s",
	"-5s", "-1h",
	"abc", "5", "5x", "s", "1e3", "off2", "0x",
	"  30s  ",
}

func FuzzParseTimeout(f *testing.F) {
	for _, s := range timeoutSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := parseTimeout(raw)

		// (1) The deadline is never negative. resolveContext arms a timeout
		// only when defaultTimeout() > 0, so a negative result would silently
		// DISABLE the deadline and let a stalled host hang the helper (and a
		// stall be misread as tamper) - the opposite of failing closed.
		if got < 0 {
			t.Fatalf("parseTimeout(%q) = %v, want >= 0 (a negative deadline disables the guard)", raw, got)
		}

		// (2) The deadline is disabled (0) for the explicit operator opt-out
		// tokens and ONLY those. Any other input - notably unparseable garbage
		// or a non-positive duration - must fail closed to a positive bound, so
		// a host cannot trick the helper into running git with no deadline.
		v := strings.TrimSpace(raw)
		optOut := v == "0" || strings.EqualFold(v, "off")
		switch {
		case optOut && got != 0:
			t.Fatalf("parseTimeout(%q) = %v, want 0 for the explicit opt-out token", raw, got)
		case !optOut && got <= 0:
			t.Fatalf("parseTimeout(%q) = %v, want > 0 (only %q/%q may disable the deadline)", raw, got, "0", "off")
		}

		// (3) A valid, positive duration is honored verbatim, not coerced to
		// the default - the operator override actually takes effect. (Both the
		// oracle and the implementation parse the same trimmed value, so they
		// agree on whatever ParseDuration accepts.)
		if d, err := time.ParseDuration(v); err == nil && d > 0 && got != d {
			t.Fatalf("parseTimeout(%q) = %v, want the parsed override %v", raw, got, d)
		}

		// (4) Determinism: a pure function of its input.
		if again := parseTimeout(raw); again != got {
			t.Fatalf("parseTimeout(%q) nondeterministic: %v then %v", raw, got, again)
		}
	})
}

func FuzzClassifyExit(f *testing.F) {
	// ctxSel selects ctx.Err()'s only production values plus an unexpected one:
	// 0=nil, 1=DeadlineExceeded, 2=Canceled, 3=some other error (never returned
	// by a real context, included as a robustness fall-through case).
	type seed struct {
		argStr        string
		ctxSel        uint8
		runErrPresent bool
		exit          int
		durNs         int64
		stderr        string
	}
	seeds := []seed{
		{"fetch origin", 0, false, 0, 0, ""},                           // success: nil runErr
		{"fetch origin", 1, true, -1, int64(5 * time.Second), ""},      // deadline, git killed (exit -1)
		{"fetch origin", 1, true, 128, 0, "fatal: missing blob 0000"},  // deadline w/ non -1 exit + tamper-ish stderr: timeout still wins
		{"fetch origin", 2, true, -1, 0, ""},                           // cancel
		{"rev-parse HEAD", 0, true, -1, 0, "exec: \"git\": not found"}, // generic: exit -1, no ctx err
		{"read remote blob", 0, true, 128, 0, "fatal: unable to read"}, // real non-zero git exit -> *GitError
		{"x", 3, true, 128, 0, "remote: nope"},                         // unexpected ctx err -> exit-based path
	}
	for _, s := range seeds {
		f.Add(s.argStr, s.ctxSel, s.runErrPresent, s.exit, s.durNs, s.stderr)
	}
	f.Fuzz(func(t *testing.T, argStr string, ctxSel uint8, runErrPresent bool, exit int, durNs int64, stderr string) {
		var ctxErr error
		switch ctxSel % 4 {
		case 1:
			ctxErr = context.DeadlineExceeded
		case 2:
			ctxErr = context.Canceled
		case 3:
			ctxErr = errors.New("unexpected ctx state")
		}
		var runErr error
		if runErrPresent {
			runErr = errors.New("run failed")
		}
		args := []string{argStr}
		dur := time.Duration(durNs)

		got := classifyExit(args, ctxErr, runErr, exit, dur, stderr)

		// (1) Success short-circuit: a nil runErr always yields nil, whatever
		// the context state, exit code, or stderr - git succeeded, no error.
		if runErr == nil {
			if got != nil {
				t.Fatalf("classifyExit with nil runErr = %v, want nil", got)
			}
			return
		}

		// With a non-nil runErr, classifyExit always returns a non-nil error.
		if got == nil {
			t.Fatalf("classifyExit with non-nil runErr returned nil (args=%q exit=%d)", argStr, exit)
		}

		var te *TimeoutError
		var ce *CanceledError
		var ge *GitError
		switch {
		case ctxErr == context.DeadlineExceeded:
			// (2) A deadline wins over the exit code. Even with a non -1 exit
			// and stderr that a classify regex would otherwise match, the result
			// is a *TimeoutError (never a *GitError), carrying the elapsed time.
			if !errors.As(got, &te) {
				t.Fatalf("deadline: got %T, want *TimeoutError", got)
			}
			if errors.As(got, &ge) {
				t.Fatalf("deadline produced a *GitError; a stall's stderr must never reach the classify table")
			}
			if te.Elapsed != dur {
				t.Fatalf("TimeoutError.Elapsed = %v, want %v", te.Elapsed, dur)
			}
		case ctxErr == context.Canceled:
			// (3) A cancel wins over the exit code, same rationale.
			if !errors.As(got, &ce) {
				t.Fatalf("cancel: got %T, want *CanceledError", got)
			}
			if errors.As(got, &ge) {
				t.Fatalf("cancel produced a *GitError")
			}
		case exit == -1:
			// (4) No deadline/cancel and a non-exit failure (spawn error, killed
			// by an external signal): a generic wrapped error that wraps runErr
			// and is none of the typed transport errors, so ClassifyTransport
			// defaults it to the conservative LocalGit.
			if errors.As(got, &te) || errors.As(got, &ce) || errors.As(got, &ge) {
				t.Fatalf("exit -1 produced a typed transport error: %T", got)
			}
			if !errors.Is(got, runErr) {
				t.Fatalf("exit -1 result does not wrap runErr: %v", got)
			}
		default:
			// (5) A real non-zero git exit: a *GitError carrying the exit code
			// and stderr verbatim - the only shape whose stderr the classify
			// table is allowed to read.
			if !errors.As(got, &ge) {
				t.Fatalf("non-zero exit: got %T, want *GitError", got)
			}
			if ge.ExitCode != exit || ge.Stderr != stderr {
				t.Fatalf("GitError = {exit %d, stderr %q}, want {exit %d, stderr %q}", ge.ExitCode, ge.Stderr, exit, stderr)
			}
		}

		// (6) End-to-end security property: a deadline/cancel ALWAYS classifies
		// as Network downstream - never a stderr-derived kind - regardless of
		// the exit code or host-influenced stderr, because classifyExit hands
		// ClassifyTransport a *TimeoutError/*CanceledError it short-circuits on
		// before the stderr regex table is ever consulted. This is the load-
		// bearing "a stall is never tamper" guarantee at its source.
		if ctxErr == context.DeadlineExceeded || ctxErr == context.Canceled {
			kind, _ := cloakerr.KindOf(ClassifyTransport("op", got))
			if kind != cloakerr.Network {
				t.Fatalf("stall classified as %v, want Network (a stall must never be tamper)\nexit=%d stderr=%q", kind, exit, stderr)
			}
		}

		// (7) Determinism: classifyExit is a pure function of its inputs.
		if again := classifyExit(args, ctxErr, runErr, exit, dur, stderr); fmt.Sprintf("%T", again) != fmt.Sprintf("%T", got) {
			t.Fatalf("classifyExit nondeterministic: %T then %T", got, again)
		}
	})
}

// classifyKind runs ClassifyTransport over a stderr string and returns its
// taxonomy kind; ClassifyTransport always yields a *cloakerr.Error, so the
// KindOf lookup always succeeds.
func classifyKind(stderr string) cloakerr.Kind {
	err := ClassifyTransport("read remote blob", &GitError{ExitCode: 128, Stderr: stderr})
	kind, _ := cloakerr.KindOf(err)
	return kind
}

// envFromBlob turns a fuzzed blob into a parent-environment slice the way
// os.Environ() shapes one: each non-empty newline-delimited line is one KEY=VAL
// entry. Empty lines are dropped so the slice carries no entry os.Environ()
// would never produce.
func envFromBlob(blob string) []string {
	var env []string
	for _, ln := range strings.Split(blob, "\n") {
		if ln != "" {
			env = append(env, ln)
		}
	}
	return env
}

// gitDirLines returns, in order, the GIT_DIR= entries of env.
func gitDirLines(env []string) []string {
	var out []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_DIR=") {
			out = append(out, kv)
		}
	}
	return out
}

func FuzzApplyGitEnv(f *testing.F) {
	// Seeds exercise an empty parent, a parent carrying a stale inherited
	// GIT_DIR (the security-critical drop), an explicit o.GitDir, scrub on, an
	// o.Env that itself re-sets GIT_DIR (a deliberate caller override that must
	// survive), and near-miss prefixes that must be kept verbatim.
	type seed struct {
		parentBlob, gitDir, envBlob string
		scrub                       bool
		inject                      uint8
	}
	seeds := []seed{
		{"", "", "", false, 0},
		{"PATH=/usr/bin\nHOME=/home/me", "/repo/.git", "", false, 0},
		{"GIT_DIR=/stale/inherited\nPATH=/bin", "/repo/.git", "", true, 0},
		{"PATH=/bin", "", "GIT_DIR=/caller/override", false, 0},
		{"GIT_DIRX=keep\nGITDIR=keep\nX=GIT_DIR=keep", "/r/.git", "", false, 0},
		{"A=1\nB=2", "scratch.git", "LANG=C\nGIT_DIR=/env/dir", true, 1},
		{"COLOR=1", "", "", true, 3},
	}
	for _, s := range seeds {
		f.Add(s.parentBlob, s.gitDir, s.envBlob, s.scrub, s.inject)
	}
	f.Fuzz(func(t *testing.T, parentBlob, gitDir, envBlob string, scrub bool, inject uint8) {
		parent := envFromBlob(parentBlob)
		// Steer: an arbitrary fuzz line almost never begins with the exact
		// "GIT_DIR=" prefix, so deliberately seed inherited GIT_DIR entries (at
		// the front, the back, and both) to reliably exercise the drop branch.
		switch inject % 4 {
		case 1:
			parent = append([]string{"GIT_DIR=/stale/front"}, parent...)
		case 2:
			parent = append(parent, "GIT_DIR=/stale/back")
		case 3:
			parent = append([]string{"GIT_DIR=/stale/a"}, append(slices.Clone(parent), "GIT_DIR=/stale/b")...)
		}
		extra := envFromBlob(envBlob)
		o := Opts{GitDir: gitDir, Scrub: scrub, Env: extra}

		got := applyGitEnv(parent, o)

		// (1) GIT_DIR isolation - the load-bearing security harm statement. The
		// only GIT_DIR= entries permitted in the child environment are the ones
		// cloak sets deliberately: o.GitDir (when non-empty, added first) followed
		// by any GIT_DIR= entry the caller put in o.Env. A GIT_DIR inherited from
		// the parent environment must NEVER survive, or it would silently point
		// the git subprocess at the wrong object store. Derived purely from
		// o.GitDir/o.Env (never the parent), so a dropped drop is caught.
		var wantGitDirs []string
		if gitDir != "" {
			wantGitDirs = append(wantGitDirs, "GIT_DIR="+gitDir)
		}
		wantGitDirs = append(wantGitDirs, gitDirLines(extra)...)
		if g := gitDirLines(got); !slices.Equal(g, wantGitDirs) {
			t.Fatalf("GIT_DIR entries = %q, want %q (a parent GIT_DIR must never survive)\nparent: %q\ngitDir: %q\nenv: %q",
				g, wantGitDirs, parent, gitDir, extra)
		}

		// (2) Preservation + ordering (a different decomposition than the build
		// loop): every NON-GIT_DIR parent entry is kept verbatim and in order at
		// the front of the result - cloak strips only the inherited GIT_DIR, never
		// drops or rewrites other inherited config (transport config like
		// core.sshCommand must keep working).
		var kept []string
		for _, kv := range parent {
			if !strings.HasPrefix(kv, "GIT_DIR=") {
				kept = append(kept, kv)
			}
		}
		if len(got) < len(kept) || !slices.Equal(got[:len(kept)], kept) {
			t.Fatalf("non-GIT_DIR parent entries not preserved as the leading segment\nparent: %q\ngot: %q", parent, got)
		}

		// (3) o.Env is appended verbatim as the trailing segment - the caller's
		// explicit environment wins and is never reordered or dropped.
		if len(extra) > 0 {
			if len(got) < len(extra) || !slices.Equal(got[len(got)-len(extra):], extra) {
				t.Fatalf("o.Env not preserved verbatim as the trailing segment\nenv: %q\ngot: %q", extra, got)
			}
		}

		// (4) Scrub harm statement (one-sided): when set, both config-disabling
		// vars must be present so the user's system/global git config cannot
		// interfere with backend object building.
		if scrub {
			if !slices.Contains(got, "GIT_CONFIG_NOSYSTEM=1") || !slices.Contains(got, "GIT_CONFIG_GLOBAL=/dev/null") {
				t.Fatalf("scrub did not disable system/global git config\ngot: %q", got)
			}
		}

		// (5) Determinism: applyGitEnv is a pure function of (parent, o).
		if again := applyGitEnv(parent, o); !slices.Equal(again, got) {
			t.Fatalf("applyGitEnv nondeterministic:\nonce:  %q\ntwice: %q", got, again)
		}
	})
}
