// Fuzz tests for the backend mirror's host-data robustness guards. cappingWriter
// is the size cap on the manifest blob read (ReadBlobBytes, the only buffered
// remote read; engine.LoadRemoteState reads manifest.age through it): it bounds
// how many bytes a malicious or buggy host can stream into client memory before
// the read is reported as oversized, so it is the defensive layer standing in
// front of manifest parsing. The existing unit test pins two fixed cases; this
// generalizes the full capping contract over arbitrary content, write-chunk
// boundaries, and limits -- exactly where an off-by-one in the room/overflow
// arithmetic would hide. parsePackBlobTree is the other host-data parser here:
// it turns the prior commit's `git ls-tree :packs` output back into the pack
// id -> blob oid map that BuildCommit reuses, so its faithfulness and robustness
// over arbitrary tree text are fuzzed alongside the capping guard. packTreeText is
// its write-side inverse -- the BuildCommit serializer that emits that tree text --
// so the real parse(serialize(packs)) == packs round trip and the sorted,
// reproducible-tree-identity contract (a property only the real serializer has) are
// fuzzed here too.
// classifyBlobRead is the integrity-critical guard of the same surface: it decides whether a failed
// manifest/pack blob read is a transport error or a Tamper alarm, over git stderr
// the untrusted host fully controls, so its anti-leak fallback and its resistance
// to sideband-injection downgrades are fuzzed here too. classifyFetchErr is the
// sibling classifier on the fetch path (engine.LoadRemoteState -> Fetch): it maps a
// failed backend fetch over host-controlled stderr to either an "empty remote"
// short-circuit (which feeds the rollback gate) or a transport error, so its
// empty-detection predicate and verbatim transport delegation are fuzzed alongside.
// pushArgs is the write-side compare-and-swap primitive on the same surface: it
// builds the backend push argv, and its load-bearing security contract is that a
// plain --force (which would clobber a concurrent winner instead of losing the
// compare-and-swap) is structurally impossible -- every force is a
// --force-with-lease carrying an explicit expected old value. The existing unit
// test pins this for one fixed (branch, commit) and two leases; the fuzz target
// generalizes it over arbitrary, adversarial branch/commit/lease.
// classifyPushResult is the write-side completion of that surface: it maps a
// backend push's host-relayed stdout/stderr to PushOK / PushCASLost (re-fetch
// and retry) / PushFailed -- the push-path sibling of the read-path classifiers
// classifyBlobRead and classifyFetchErr. Its load-bearing contract is that
// PushOK is returned only when git itself reported no error (the engine commits
// and persists a push only on PushOK, so a spurious PushOK would record a
// publish that never landed), and that the compare-and-swap-lost retry fires
// exactly on git's documented rejection phrases; the fuzz target pins both over
// arbitrary, adversarial host output.
package backend

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

// FuzzCappingWriter pins cappingWriter's contract over arbitrary content fed in
// arbitrary write chunks against an arbitrary limit. Whatever the chunking, the
// underlying writer must receive exactly the first min(len(content), limit)
// bytes of the content unchanged; every Write must acknowledge the full chunk
// (memory stays bounded because the overflow is discarded while git streams to
// completion); and overflow must be set exactly when the content exceeds the
// limit. The oracle recomputes the expected kept prefix independently from the
// concatenated input, so it cannot merely restate the implementation. The limit
// is fuzzed as a uint32 (non-negative by construction, matching the positive
// maxManifestBytes constant the production caller always passes).
func FuzzCappingWriter(f *testing.F) {
	// Seeds: under limit, single straddling write, empty content, exact fit,
	// zero limit (everything overflows), and a chunk size that splits the
	// content around the limit boundary.
	f.Add([]byte("hello"), uint32(10), uint16(5))
	f.Add([]byte("abcdef"), uint32(4), uint16(6))
	f.Add([]byte(""), uint32(0), uint16(1))
	f.Add([]byte("exact"), uint32(5), uint16(1))
	f.Add([]byte("over"), uint32(0), uint16(2))
	f.Add([]byte("boundary-straddle"), uint32(7), uint16(4))

	f.Fuzz(func(t *testing.T, content []byte, limit32 uint32, chunk16 uint16) {
		limit := int64(limit32)
		chunk := int(chunk16)
		if chunk < 1 {
			chunk = 1
		}

		var buf strings.Builder
		cw := &cappingWriter{w: &buf, limit: limit}

		// Feed the content in chunk-sized writes, exactly as a streaming git
		// cat-file would deliver it. strings.Builder never short-writes or
		// errors, so every Write must report the full chunk length and nil --
		// the property that lets the streaming git process run to completion.
		for off := 0; off < len(content); off += chunk {
			end := off + chunk
			if end > len(content) {
				end = len(content)
			}
			p := content[off:end]
			n, err := cw.Write(p)
			if err != nil || n != len(p) {
				t.Fatalf("Write(%d bytes) = (%d, %v), want (%d, nil)", len(p), n, err, len(p))
			}
		}

		// Independently compute the expected kept prefix: min(len, limit) bytes.
		want := int64(len(content))
		if limit < want {
			want = limit
		}

		got := buf.String()
		if int64(len(got)) != want {
			t.Fatalf("kept %d bytes, want %d (content=%d, limit=%d)", len(got), want, len(content), limit)
		}
		// The kept bytes must be a faithful, unmodified prefix of the content.
		if got != string(content[:want]) {
			t.Fatalf("kept bytes are not a faithful prefix (content=%d, limit=%d)", len(content), limit)
		}
		// cw.n must equal exactly the bytes forwarded to the underlying writer.
		if cw.n != want {
			t.Fatalf("cw.n = %d, want %d", cw.n, want)
		}
		// Overflow is recorded exactly when the content exceeds the limit.
		if wantOverflow := int64(len(content)) > limit; cw.overflow != wantOverflow {
			t.Fatalf("overflow = %v, want %v (content=%d, limit=%d)", cw.overflow, wantOverflow, len(content), limit)
		}
	})
}

// FuzzParsePackBlobTree pins parsePackBlobTree as the faithful inverse of the
// pack-tree serialization that BuildCommit writes. PackBlobOIDs reads the prior
// commit's `git ls-tree <commit>:packs` output through parsePackBlobTree to
// recover the pack id -> blob oid map, and treePackBlobs then reuses those exact
// blobs in the next commit's tree (engine/push.go); BuildCommit re-emits every
// entry as "100644 blob <oid>\t<id>.age" (backend.go:319). So the production
// contract is precisely: parse(serialize(map)) == map. The pack filenames in
// that tree are host-influenced (whatever was pushed to the mirror), so the
// parser must also stay robust against arbitrary, malformed ls-tree text.
//
// The oracle is non-circular: the expected map is built from the writer's format
// (the BuildCommit serialization contract), not from re-running the parser's own
// skip/cut logic. Two fuzz inputs drive it -- `spec` becomes a set of well-formed
// blob entries (one per line, "<oid> <id>", duplicate ids exercising last-wins),
// and `noise` becomes tab-free junk lines interleaved between them. A line with
// no tab is always rejected at the strings.Cut step, so tab-free noise is
// guaranteed not to contribute, keeping the round-trip oracle exact while still
// forcing the parser to skip arbitrary garbage. A final raw parse over the
// unsanitized inputs (tabs included) exercises the type/field-count/cut reject
// branches for no-panic.
func FuzzParsePackBlobTree(f *testing.F) {
	// Seeds: a plain entry, duplicate id (last wins), empty, a name with spaces,
	// an empty id, plus noise shapes that must all be skipped -- non-blob type,
	// a two-field meta (missing oid), and a line with no tab.
	f.Add("a1b2c3 deadbeef", "")
	f.Add("oid1 dup\noid2 dup", "")
	f.Add("", "")
	f.Add("cafef00d pack with spaces", "no-tab-junk-line")
	f.Add("d00d ", "100644 tree abc\tt.age\n100644 blob\tn.age")
	f.Add("11 a\n22 b\n33 c", "\t\t\trandom garbage\nmore")

	f.Fuzz(func(t *testing.T, spec, noise string) {
		// Build the model and the matching well-formed ls-tree lines. A spec line
		// "<oid> <id>" yields an entry only when it round-trips BuildCommit's
		// format exactly: oid must be non-empty and contain no whitespace (it is
		// fields[2] of a 3-field "100644 blob <oid>" meta, and strings.Fields
		// trims any surrounding whitespace -- so an oid like "0\r" would come back
		// as "0"), and id must contain no tab or newline (a tab would move the
		// strings.Cut split point and a newline would forge an extra line). With
		// those held, the parser's TrimSuffix(name, ".age") recovers exactly the
		// id that was appended and fields[2] recovers exactly the oid.
		want := map[string]string{}
		var lines []string
		for _, l := range strings.Split(spec, "\n") {
			oid, id, ok := strings.Cut(l, " ")
			if !ok || oid == "" || strings.ContainsFunc(oid, unicode.IsSpace) || strings.ContainsAny(id, "\t\n") {
				continue
			}
			lines = append(lines, "100644 blob "+oid+"\t"+id+".age")
			want[id] = oid // duplicate ids: last well-formed line wins, as in the map
		}

		// Interleave tab-free noise lines between the well-formed entries. The
		// relative order of the entries is preserved, so the last-wins model still
		// holds; the tab-free junk must be skipped and leave the result untouched.
		noiseLines := strings.Split(noise, "\n")
		var out []string
		for i, vl := range lines {
			if i < len(noiseLines) {
				out = append(out, strings.ReplaceAll(noiseLines[i], "\t", ""))
			}
			out = append(out, vl)
		}
		for i := len(lines); i < len(noiseLines); i++ {
			out = append(out, strings.ReplaceAll(noiseLines[i], "\t", ""))
		}

		got := parsePackBlobTree(strings.Join(out, "\n"))
		if got == nil {
			t.Fatal("parsePackBlobTree returned a nil map")
		}
		if !maps.Equal(got, want) {
			t.Fatalf("round-trip mismatch:\n got  %v\n want %v", got, want)
		}

		// Robustness: the raw, unsanitized inputs carry arbitrary tabs and so
		// reach the type-mismatch, field-count, and cut reject branches. The only
		// contract here is no panic and a non-nil result.
		if parsePackBlobTree(spec) == nil || parsePackBlobTree(noise) == nil {
			t.Fatal("parsePackBlobTree returned a nil map on raw input")
		}
	})
}

// FuzzClassifyBlobRead pins classifyBlobRead, the backend decision that turns a
// failed manifest/pack blob read into either a transport error or a Tamper
// alarm. The host serves the blob and controls the git stderr, so this is the
// integrity-critical classifier guarding the encrypt/decrypt Tamper taxonomy: a
// flaky network must surface as its transport kind (never a false TAMPER that a
// sync wrapper escalates instead of retrying), while content the manifest
// promised but that is unreadable for any unrecognized reason must escalate to
// Tamper.
//
// Two properties hold for ANY host stderr. (1) The result is always a fully
// classified *cloakerr.Error whose kind is NEVER LocalGit: backend folds the
// gitx LocalGit fail-safe default into the stricter Tamper, so an unrecognized
// failure can never leak out as a benign local-git error that a caller might
// treat as non-integrity. (2) The kind matches the documented contract,
// re-derived through the public, separately-fuzzed gitx primitives -- strip the
// host sideband, classify the sanitized stderr, fold a LocalGit result to
// Tamper -- which verifies the wiring (the strip happens before classification,
// the LocalGit default escalates) without restating classifyBlobRead's body. A
// non-GitError failure is an unclassifiable local error and so must escalate to
// Tamper.
func FuzzClassifyBlobRead(f *testing.F) {
	seeds := []struct {
		path   string
		stderr string
		git    bool
	}{
		{"manifest.age", "", true},
		{"packs/x.age", "fatal: bad object deadbeef", true},
		{"packs/x.age", "ssh: Could not resolve host: example.invalid", true},
		{"packs/x.age", "git@github.com: Permission denied (publickey).", true},
		{"manifest.age", "remote: connection reset by the host\nfatal: bad object deadbeef", true},
		{"packs/x.age", "fatal: unable to access: Connection refused", true},
		{"packs/x.age", "some local breakage", false},
	}
	for _, s := range seeds {
		f.Add(s.path, s.stderr, s.git)
	}
	f.Fuzz(func(t *testing.T, path, stderr string, asGit bool) {
		var err error
		if asGit {
			err = &gitx.GitError{Args: []string{"cat-file"}, ExitCode: 128, Stderr: stderr}
		} else {
			err = errors.New(stderr)
		}

		got := classifyBlobRead(path, err)

		// (1) Always fully classified, and never the leaky LocalGit fail-safe:
		// the backend's conservative default for an unreadable blob is Tamper.
		kind, ok := cloakerr.KindOf(got)
		if !ok {
			t.Fatalf("classifyBlobRead returned an unclassified error: %v", got)
		}
		if kind == cloakerr.LocalGit {
			t.Fatalf("classifyBlobRead leaked LocalGit (must fold to Tamper): %v", got)
		}

		// (2) The kind matches the documented contract, derived through the
		// public gitx primitives rather than classifyBlobRead's own body: a
		// recognized transport failure surfaces as itself; anything the
		// classifier cannot place (LocalGit) escalates to Tamper.
		var want cloakerr.Kind
		if asGit {
			stripped := gitx.StripServerSideband(stderr)
			ref := gitx.ClassifyTransport("ref", &gitx.GitError{ExitCode: 128, Stderr: stripped})
			refKind, _ := cloakerr.KindOf(ref)
			if refKind == cloakerr.LocalGit {
				want = cloakerr.Tamper
			} else {
				want = refKind
			}
		} else {
			want = cloakerr.Tamper
		}
		if kind != want {
			t.Fatalf("classified %v, want %v (stderr=%q asGit=%v)", kind, want, stderr, asGit)
		}

		// Classification is a pure function of its inputs.
		if again, _ := cloakerr.KindOf(classifyBlobRead(path, err)); again != kind {
			t.Fatalf("non-deterministic classification: %v then %v", kind, again)
		}
	})
}

// FuzzBlobReadSidebandCannotDowngrade is the security oracle for classifyBlobRead
// at the layer that matters: a withholding host relays arbitrary "remote:"-prefixed
// sideband text into git's stderr and must NOT be able to change the blob-read
// classification -- in particular it must never downgrade a genuine missing-blob
// Tamper into a retryable transport kind that a sync wrapper would silently retry
// instead of alarming. gitx's FuzzSidebandInjectionCannotDowngrade pins this for
// the ClassifyTransport primitive; this pins it for the real backend consumer,
// which adds the LocalGit->Tamper escalation the primitive cannot express -- so it
// is precisely the missing-blob-stays-Tamper harm that is exercised here.
func FuzzBlobReadSidebandCannotDowngrade(f *testing.F) {
	seeds := []struct{ base, payload string }{
		{"fatal: bad object deadbeef", "connection reset"},
		{"fatal: missing object 0000", "could not resolve host github.com"},
		{"", "repository 'x' not found\nAuthentication failed"},
		{"ssh: connect to host: Connection refused", "early EOF"},
		{"remote: a\nfatal: local breakage", ""},
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

		classify := func(stderr string) cloakerr.Kind {
			err := classifyBlobRead("packs/x.age", &gitx.GitError{ExitCode: 128, Stderr: stderr})
			k, _ := cloakerr.KindOf(err)
			return k
		}

		// Injecting the relayed sideband before or after the genuine
		// client-origin stderr must not change the classification: the host has
		// zero influence over the post-strip taxonomy, so it can never downgrade
		// an unreadable blob's Tamper into a retryable transport kind.
		want := classify(base)
		for _, combined := range []string{
			relayed.String() + "\n" + base,
			base + "\n" + relayed.String(),
		} {
			if got := classify(combined); got != want {
				t.Fatalf("sideband injection changed blob-read classification: want %v got %v\nbase:    %q\npayload: %q", want, got, base, payload)
			}
		}
	})
}

// FuzzClassifyFetchErr pins classifyFetchErr, the fetch-path counterpart to
// classifyBlobRead. A failed backend `git fetch` is mapped to one of two
// outcomes over host-controlled stderr: the genuine "the backend branch does
// not exist" signal short-circuits to an empty-remote result (head "", empty
// true, nil error), and everything else is reported as a transport error via
// gitx.ClassifyTransport. The empty short-circuit is security-relevant because
// LoadRemoteState routes it straight into the rollback gate (CheckPin(nil, "")),
// so the classifier must declare "empty" ONLY when git's stderr genuinely
// carries the missing-ref signal, never for an arbitrary transport failure.
//
// The target is fuzzed with partial=false: that is the steady state once the
// promisor mirror is established and, more importantly, it is the only
// side-effect-free configuration -- the partial+filter-rejected branch recurses
// into Fetch (a git subprocess), so it is out of scope for a pure parser fuzz.
// With partial=false the function is a pure function of (stderr, err).
//
// Three properties hold for ANY host stderr. (1) head is always "": no
// host-influenced bytes leak into the advertised tip on the failure path. (2)
// empty is true exactly when the lowercased stderr contains one of git's two
// missing-ref phrases -- an oracle re-derived independently from the raw input,
// so it cannot merely restate the implementation -- and an empty result always
// carries a nil error. (3) A non-empty result delegates verbatim to
// gitx.ClassifyTransport (same op, no folding), so its kind matches the
// separately-fuzzed primitive; unlike classifyBlobRead this path does NOT fold
// LocalGit, because an unrecognized fetch failure is a retryable transport
// outcome, not the manifest-promised-content-unreadable Tamper taxonomy.
//
// classifyFetchErr deliberately classifies on the UN-stripped stderr (no
// StripServerSideband, unlike classifyBlobRead): its "empty" outcome escalates
// through CheckPin to a Rollback alarm when the remote is pinned, so a host has
// no downgrade incentive to forge it -- the opposite of the blob-read path where
// "empty"/transport is the benign class a host would inject toward. The empty
// predicate (property 2) pins that the signal is never spuriously synthesized.
func FuzzClassifyFetchErr(f *testing.F) {
	seeds := []struct {
		stderr string
		asGit  bool
	}{
		{"fatal: couldn't find remote ref refs/heads/main", true},
		{"warning: no matching refs found", true},
		{"COULDN'T FIND REMOTE REF refs/heads/x", true},               // uppercase: exercises ToLower
		{"remote: couldn't find remote ref\nfatal: bad object", true}, // sideband-relayed: still empty (no strip)
		{"fatal: unable to access: Connection refused", true},
		{"ssh: Could not resolve host: example.invalid", true},
		{"git@github.com: Permission denied (publickey).", true},
		{"", true},
		{"some local breakage", false},
	}
	for _, s := range seeds {
		f.Add(s.stderr, s.asGit)
	}
	f.Fuzz(func(t *testing.T, stderr string, asGit bool) {
		// Mirror production: Fetch hands classifyFetchErr the captured stderr and
		// the run error carrying that same stderr. partial=false keeps the target
		// pure (the filter-rejected recursion is unreachable).
		var err error
		if asGit {
			err = &gitx.GitError{Args: []string{"fetch"}, ExitCode: 128, Stderr: stderr}
		} else {
			err = errors.New(stderr)
		}
		b := &Backend{}

		head, empty, gotErr := b.classifyFetchErr(stderr, err)

		// (1) The failure path never advertises a host-influenced tip.
		if head != "" {
			t.Fatalf("classifyFetchErr returned head %q, want empty", head)
		}

		// (2) Independently re-derive the empty predicate from the raw stderr.
		low := strings.ToLower(stderr)
		wantEmpty := strings.Contains(low, "couldn't find remote ref") ||
			strings.Contains(low, "no matching refs")
		if empty != wantEmpty {
			t.Fatalf("empty = %v, want %v (stderr=%q)", empty, wantEmpty, stderr)
		}
		if empty {
			// An empty remote is reported cleanly, never as an error.
			if gotErr != nil {
				t.Fatalf("empty result carried a non-nil error: %v", gotErr)
			}
			return
		}

		// (3) A non-empty result is a transport error delegated verbatim to the
		// separately-fuzzed gitx primitive (no folding of LocalGit here).
		if gotErr == nil {
			t.Fatal("non-empty result returned a nil error")
		}
		kind, ok := cloakerr.KindOf(gotErr)
		if !ok {
			t.Fatalf("classifyFetchErr returned an unclassified error: %v", gotErr)
		}
		refKind, _ := cloakerr.KindOf(gitx.ClassifyTransport("fetch backend branch", err))
		if kind != refKind {
			t.Fatalf("transport classified %v, want %v (stderr=%q asGit=%v)", kind, refKind, stderr, asGit)
		}

		// The classification is a pure function of its inputs.
		_, again, againErr := b.classifyFetchErr(stderr, err)
		if again != empty {
			t.Fatalf("non-deterministic empty: %v then %v", empty, again)
		}
		if k2, _ := cloakerr.KindOf(againErr); k2 != kind {
			t.Fatalf("non-deterministic classification: %v then %v", kind, k2)
		}
	})
}

// FuzzPushArgs pins pushArgs as cloak's compare-and-swap push-command builder.
// The backend never blind-force-pushes: PushFF (lease=="") emits a plain
// fast-forward whose CAS comes from git's own ref-changed-since-discovery
// rejection, and PushLease (lease!="") emits a --force-with-lease carrying an
// explicit expected old value, so a concurrent winner's commit is detected and
// the push loses the race rather than clobbering it. A plain --force/-f would
// defeat that and silently overwrite another client's accepted state, so it must
// be impossible to produce for ANY input -- including adversarial branch/commit/
// lease that smuggle in flag-shaped or delimiter-shaped substrings ("--force",
// ":", "refs/heads/", whitespace). The unit test pins this for one fixed
// (branch, commit) and two leases; this generalizes it. pushArgs is pure, so
// there is no production change.
//
// The force-flag scan looks only at the flags region args[1:len-2] -- between
// the "push" subcommand and the trailing "origin <refspec>" positionals. The
// refspec is a positional value git never parses as a flag, and an adversarial
// commit/branch can make it begin with "--force"; excluding the positionals
// keeps the scan from false-positiving on that while still covering every flag
// the builder can actually emit (which is only --porcelain plus the optional
// lease).
func FuzzPushArgs(f *testing.F) {
	seeds := []struct{ branch, commit, lease string }{
		{"cloak", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", ""},                                         // production fast-forward
		{"cloak", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "0123456789abcdef0123456789abcdef01234567"}, // production lease
		{"main", "", ""},                   // empty commit
		{"--force", "cafe", "--force"},     // flag-shaped tokens in every slot
		{"a:b", "x", "c:d"},                // embedded refspec/lease delimiter
		{"refs/heads/x", "y", "z"},         // embedded ref prefix
		{"", "commit", "lease"},            // empty branch
		{"br anch\n", "co\tmmit", "le se"}, // whitespace / control bytes
	}
	for _, s := range seeds {
		f.Add(s.branch, s.commit, s.lease)
	}

	f.Fuzz(func(t *testing.T, branch, commit, lease string) {
		args := pushArgs(branch, commit, lease)

		assertPushSkeleton(t, args, branch, commit, lease)
		assertNoBareForceFlag(t, args)
		assertLeaseForce(t, args, branch, lease)

		// (4) Pure function: identical inputs yield an identical argv.
		if again := pushArgs(branch, commit, lease); !slices.Equal(again, args) {
			t.Fatalf("non-deterministic argv: %v then %v", args, again)
		}
	})
}

// assertPushSkeleton pins pushArgs's command skeleton:
// `push --porcelain [<lease>] origin <refspec>`. Exactly 4 args without a lease,
// 5 with one -- no extra or dropped arg (a dropped --porcelain would break
// push()'s result parsing) -- with origin as the remote and the exact
// <commit>:refs/heads/<branch> refspec.
func assertPushSkeleton(t *testing.T, args []string, branch, commit, lease string) {
	t.Helper()
	wantLen := 4
	if lease != "" {
		wantLen = 5
	}
	if len(args) != wantLen {
		t.Fatalf("len(args) = %d, want %d: %v", len(args), wantLen, args)
	}
	if args[0] != "push" || args[1] != "--porcelain" {
		t.Fatalf("argv does not start with `push --porcelain`: %v", args)
	}
	if args[len(args)-2] != "origin" {
		t.Fatalf("remote is not `origin`: %v", args)
	}
	if refspec := commit + ":refs/heads/" + branch; args[len(args)-1] != refspec {
		t.Fatalf("refspec = %q, want %q", args[len(args)-1], refspec)
	}
}

// assertNoBareForceFlag pins pushArgs's headline security invariant: no arg is
// ever a plain/unguarded force flag, for ANY input. Every arg is a fixed token,
// the "--force-with-lease=refs/heads/...:..." form, or a positional that always
// carries ":refs/heads/" (the refspec) -- so none can equal a bare force flag.
// It is the documented "a plain --force is structurally impossible" contract
// stated as a forbidden-value property.
func assertNoBareForceFlag(t *testing.T, args []string) {
	t.Helper()
	for _, a := range args {
		switch a {
		case "--force", "-f", "--force-with-lease", "--force-if-includes":
			t.Fatalf("plain/unguarded force flag %q in argv: %v", a, args)
		}
	}
}

// assertLeaseForce pins that a force flag is present IFF a lease was requested,
// and when present it is exactly the --force-with-lease form carrying
// refs/heads/<branch> and the caller's explicit expected value <lease> -- never
// a remembered or empty value that would weaken the compare-and-swap. Only the
// flags region args[1:len-2] is scanned, so an adversarial refspec positional is
// never read as a flag.
func assertLeaseForce(t *testing.T, args []string, branch, lease string) {
	t.Helper()
	forceFlags := 0
	for _, a := range args[1 : len(args)-2] {
		if strings.HasPrefix(a, "--force") {
			forceFlags++
			if want := "--force-with-lease=refs/heads/" + branch + ":" + lease; a != want {
				t.Fatalf("force flag = %q, want explicit lease %q", a, want)
			}
		}
	}
	if hasForce := forceFlags > 0; hasForce != (lease != "") {
		t.Fatalf("force present = %v, want %v (lease=%q)", hasForce, lease != "", lease)
	}
}

// FuzzClassifyPushResult pins classifyPushResult, which maps a backend push's
// outcome (git's stdout, stderr, and run error) to PushOK / PushCASLost /
// PushFailed. The classification is host-influenced: a remote's rejection is
// relayed through git's stderr, so an adversarial or noisy host fully controls
// the scanned text. The oracle re-derives the result with an independent forward
// scan over a literal copy of the documented compare-and-swap-lost phrases (so
// an accidental edit to the production marker set diverges and fails here, and
// the re-scan catches a dropped lowercase, a reordered/short-circuited loop, or
// a wrong returned marker). The headline safety property -- PushOK is returned
// IF AND ONLY IF git reported no error -- is asserted independently of the
// marker set, because the engine commits a push only on PushOK so a spurious
// success would record a publish that never landed.
func FuzzClassifyPushResult(f *testing.F) {
	f.Add("", "", false)                                            // success: no output, no error
	f.Add("", "", true)                                             // bare failure, no recognizable marker
	f.Add("", "! [rejected] main -> main (non-fast-forward)", true) // real git rejection on stderr
	f.Add("STALE INFO", "", true)                                   // uppercased marker -> case-insensitive match
	f.Add("error: failed to update ref refs/heads/main", "", true)  // marker embedded in noise
	f.Add("fetch first\nstale info", "", true)                      // two markers, first one wins
	f.Add("fatal: unable to access remote", "", true)               // genuine failure, not a CAS loss
	f.Add("", "cannot lock ref refs/heads/cloak", true)             // marker on stderr only

	f.Fuzz(func(t *testing.T, stdout, stderr string, hasErr bool) {
		// wantMarkers mirrors the documented git compare-and-swap-lost phrases
		// independently of the production casLostMarkers slice.
		wantMarkers := []string{
			"non-fast-forward", "fetch first", "stale info",
			"cannot lock ref", "failed to update ref",
		}

		var runErr error
		if hasErr {
			runErr = errors.New("git push failed")
		}

		res, marker := classifyPushResult(stdout, stderr, runErr)

		assertPushResultOracle(t, stdout, stderr, runErr, res, marker, wantMarkers)

		// (2) Load-bearing safety, asserted independently of the marker set:
		// PushOK IFF git reported no error. The engine commits/persists a push
		// only on PushOK, so a PushOK on a failed push would record a publish that
		// never landed, and a CAS loss or failure must never masquerade as success.
		if (res == PushOK) != (runErr == nil) {
			t.Fatalf("PushOK=%v but (err==nil)=%v: PushOK must mean git reported no error",
				res == PushOK, runErr == nil)
		}

		assertPushResultShape(t, res, marker, stdout, stderr, wantMarkers)

		// (4) Pure function: identical inputs yield an identical classification.
		if res2, marker2 := classifyPushResult(stdout, stderr, runErr); res2 != res || marker2 != marker {
			t.Fatalf("non-deterministic: (%v, %q) then (%v, %q)", res, marker, res2, marker2)
		}
	})
}

// assertPushResultOracle is classifyPushResult's full-contract forward
// re-derivation: a nil run error short-circuits to PushOK before any scan;
// otherwise the FIRST documented marker present in the lowercased combined output
// (stdout, newline, stderr) wins as PushCASLost, else PushFailed.
func assertPushResultOracle(t *testing.T, stdout, stderr string, runErr error, res PushResult, marker string, wantMarkers []string) {
	t.Helper()
	wantRes, wantMarker := PushFailed, ""
	if runErr == nil {
		wantRes, wantMarker = PushOK, ""
	} else {
		combined := strings.ToLower(stdout + "\n" + stderr)
		for _, m := range wantMarkers {
			if strings.Contains(combined, m) {
				wantRes, wantMarker = PushCASLost, m
				break
			}
		}
	}
	if res != wantRes || marker != wantMarker {
		t.Fatalf("classifyPushResult(%q, %q, err=%v) = (%v, %q), want (%v, %q)",
			stdout, stderr, runErr != nil, res, marker, wantRes, wantMarker)
	}
}

// assertPushResultShape pins that the result is always one of the three defined
// outcomes, and a marker is set exactly when the result is PushCASLost. When set
// it is a real documented marker actually present in the lowercased output --
// never fabricated, since the caller logs it as the observed signal.
func assertPushResultShape(t *testing.T, res PushResult, marker, stdout, stderr string, wantMarkers []string) {
	t.Helper()
	switch res {
	case PushOK, PushFailed:
		if marker != "" {
			t.Fatalf("res %v carries marker %q, want empty", res, marker)
		}
	case PushCASLost:
		if !slices.Contains(wantMarkers, marker) {
			t.Fatalf("PushCASLost marker %q is not a documented marker", marker)
		}
		if !strings.Contains(strings.ToLower(stdout+"\n"+stderr), marker) {
			t.Fatalf("PushCASLost marker %q not present in the output", marker)
		}
	default:
		t.Fatalf("undefined PushResult %v", res)
	}
}

// FuzzPackTreeText pins packTreeText, the write-side inverse of parsePackBlobTree.
// BuildCommit serializes the pack id -> blob oid map into the `git mktree` input
// for the packs/ subtree, one "100644 blob <oid>\t<id>.age" entry per id; a later
// fetch reads that tree back through parsePackBlobTree for blob reuse. So the
// production contract is parse(serialize(packs)) == packs, and FuzzParsePackBlobTree
// covers the parse side -- but it does so against a HAND-MODELED copy of the writer's
// format string, never running the real serializer or its sorting. This target runs
// the real packTreeText, so a drift in BuildCommit's format string (which the parse
// fuzzer's own copy would not catch) breaks the round trip here.
//
// Two contracts are pinned beyond the round trip. First, the output is sorted by id:
// the same pack set must serialize byte-identically so the resulting tree -- and thus
// the commit -- has a reproducible identity (the compare-and-swap push depends on it),
// a property the parse fuzzer never exercises because it never runs the sort. Second,
// determinism over a Go map's randomized iteration order. The clean predicate matches
// FuzzParsePackBlobTree's: an id round-trips iff it carries no tab (the Cut delimiter)
// or newline (the line delimiter) -- the trailing ".age" shields any other byte, since
// TrimSuffix(id+".age", ".age") == id always -- and an oid round-trips iff it is
// non-empty and whitespace-free (it must be exactly fields[2] of a 3-field meta).
func FuzzPackTreeText(f *testing.F) {
	// Seeds: two clean entries, an empty map (raw with no space), a duplicate id
	// (last value wins in the map), an id bearing an internal space (clean -- it
	// lives after the tab), an id containing ".age", and unclean id/oid shapes.
	f.Add("aa bb\ncc dd")
	f.Add("")
	f.Add("dup oid1\ndup oid2")
	f.Add("id with internal space oid")
	f.Add(".age aaaa\nx.age bbbb")
	f.Add("bad\tid oid")       // tab in id (unclean)
	f.Add("id oid with space") // whitespace in oid (unclean)
	f.Add("emptyoid \nb cccc") // empty oid (unclean)

	f.Fuzz(func(t *testing.T, raw string) {
		packs := buildPacksFromRaw(raw)

		got := packTreeText(packs)

		// Determinism over a map's randomized iteration order, for ANY input.
		if got != packTreeText(packs) {
			t.Fatal("packTreeText is not deterministic")
		}

		// For ANY input: an empty map serializes to "", and a non-empty map's
		// output ends in the per-entry trailing newline.
		if len(packs) == 0 {
			if got != "" {
				t.Fatalf("empty map serialized to %q, want empty", got)
			}
			return
		}
		if !strings.HasSuffix(got, "\n") {
			t.Fatalf("serialization does not end in a newline: %q", got)
		}

		// The per-entry, sort, and round-trip checks require a clean pack set: an
		// id bearing a tab or newline (or an oid bearing whitespace) re-frames the
		// serialized lines -- exactly the shape the parser is allowed to drop -- so
		// it is out of scope for a faithful round trip, just as in
		// FuzzParsePackBlobTree.
		if !packsAreClean(packs) {
			return
		}

		assertPackTreeEntries(t, got, packs)
	})
}

// buildPacksFromRaw builds a packs map from fuzzed "<id> <oid>" lines (the first
// space splits, so an id may carry later spaces). Duplicate ids take the last
// line's oid, exactly as a map assignment would.
func buildPacksFromRaw(raw string) map[string]string {
	packs := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		id, oid, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		packs[id] = oid
	}
	return packs
}

// packsAreClean reports whether every entry round-trips packTreeText's
// serialization: an id must carry no tab or newline (the Cut and line
// delimiters) and an oid must be non-empty and whitespace-free (it must be
// exactly fields[2] of a 3-field meta). An unclean entry re-frames the
// serialized lines and is out of scope for a faithful round trip.
func packsAreClean(packs map[string]string) bool {
	for id, oid := range packs {
		if strings.ContainsAny(id, "\t\n") || oid == "" || strings.ContainsFunc(oid, unicode.IsSpace) {
			return false
		}
	}
	return true
}

// assertPackTreeEntries pins the per-entry, sort, and round-trip contracts on a
// clean pack set: each entry is exactly one line "100644 blob <oid>\t<id>.age",
// the ids appear in ascending order -- the reproducible-tree-identity contract
// that only the real serializer's sort provides (and that the parse-side fuzzer
// never exercises) -- and the parser recovers the exact map the serializer was
// handed.
func assertPackTreeEntries(t *testing.T, got string, packs map[string]string) {
	t.Helper()
	if n := strings.Count(got, "\n"); n != len(packs) {
		t.Fatalf("emitted %d lines for %d packs", n, len(packs))
	}
	var ids []string
	for _, e := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		meta, name, ok := strings.Cut(e, "\t")
		if !ok || !strings.HasSuffix(name, ".age") {
			t.Fatalf("entry %q is not <meta>\\t<id>.age", e)
		}
		id := strings.TrimSuffix(name, ".age")
		if want := "100644 blob " + packs[id]; meta != want {
			t.Fatalf("entry meta %q, want %q", meta, want)
		}
		ids = append(ids, id)
	}
	if !slices.IsSorted(ids) {
		t.Fatalf("ids are not sorted ascending: %v", ids)
	}

	// Round trip through BOTH real production functions: the parser recovers
	// the exact map the serializer was handed.
	if back := parsePackBlobTree(got); !maps.Equal(back, packs) {
		t.Fatalf("round-trip mismatch:\n got  %v\n want %v", back, packs)
	}
}
