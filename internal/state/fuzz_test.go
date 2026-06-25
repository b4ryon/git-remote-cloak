// Fuzz tests for per-remote state: directory naming (DirName), the
// rollback-protection decision (CheckPin), the repository-identity
// substitution gate (CheckRepoID), the rollback-pin deserializer (LoadPin),
// and the applied-pack-set parser/round-trip (AppliedSet/MarkApplied).
// AppliedSet parses the on-disk "applied" file -- arbitrary bytes a host (or
// filesystem corruption) could leave there -- into the set of pack ids the
// engine treats as already indexed; that set feeds packSkippable, which decides
// whether to skip DOWNLOADING a manifest pack, so a parse that fabricated or
// mangled an id (over-reporting a pack as applied) could let a needed pack be
// silently skipped. MarkApplied is its writer; the two form the persistence
// round-trip the skip gate depends on. LoadPin parses the on-disk "generation"
// file -- arbitrary bytes a host (or filesystem corruption) could leave there --
// back into the Pin{Generation, ManifestHash} that CheckPin trusts; a parse
// that silently succeeded with a wrong (e.g. zeroed) generation would defeat the
// very rollback check CheckPin performs, so its fail-closed/round-trip contract
// is security-load-bearing. DirName turns the
// helper-invocation arguments git hands cloak (the remote name, which git
// controls, and the remote URL, which is host/config influenced) into the
// single directory component used under .git/cloak/<name>/. It is the
// path-traversal guard standing between attacker/host-influenced strings and a
// filepath.Join against the cloak base: a result of "", ".", "..", or anything
// carrying a separator would let the per-remote state escape or alias the base
// directory (clobbering another remote's rollback pin / applied set, or writing
// outside cloak/ entirely). The two existing unit tests pin a handful of fixed
// cases; this generalizes the full safety contract -- always a non-empty,
// separator-free, non-dot single component that stays strictly one level below
// the base -- over arbitrary names and URLs, which is exactly where a regex or
// dot-name gap would hide. The state package previously had zero fuzz coverage.
package state

import (
	"encoding/hex"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

func FuzzDirName(f *testing.F) {
	f.Add("origin", "ssh://host/repo")
	f.Add("", "ssh://host/repo")
	f.Add(".", "u")
	f.Add("..", "u")
	f.Add("...", "u")
	f.Add("", "")
	f.Add("a/b", "u")
	f.Add("../../etc/passwd", "u")
	f.Add("a\\b", "u")
	f.Add("a\x00b", "u")
	f.Add("with space", "u")
	f.Add("cloak::git@x:y", "cloak::git@x:y")
	f.Add("url-deadbeef", "u")

	const base = "/repo/.git/cloak"

	f.Fuzz(func(t *testing.T, remoteName, url string) {
		name := DirName(remoteName, url)

		// A single, safe path component: an empty name would resolve to the
		// base itself and "."/".." would alias or escape it.
		if name == "" {
			t.Fatalf("DirName(%q, %q) returned an empty name", remoteName, url)
		}
		if name == "." || name == ".." {
			t.Fatalf("DirName(%q, %q) = %q, a dot name that aliases/escapes the base", remoteName, url, name)
		}
		if strings.ContainsRune(name, '/') || strings.ContainsRune(name, filepath.Separator) {
			t.Fatalf("DirName(%q, %q) = %q contains a path separator", remoteName, url, name)
		}

		// The load-bearing safety property expressed through the real consumer:
		// joining the name onto the cloak base must land strictly one level
		// below the base (its parent is exactly the cleaned base) and need no
		// cleaning, so no input can traverse out of cloak/.
		joined := filepath.Join(base, name)
		if filepath.Dir(joined) != filepath.Clean(base) {
			t.Fatalf("DirName(%q, %q) = %q escapes the base: Join -> %q", remoteName, url, name, joined)
		}
		if joined != filepath.Clean(joined) {
			t.Fatalf("DirName(%q, %q) = %q yields a non-clean path %q", remoteName, url, name, joined)
		}

		// Deterministic: the directory must be stable across invocations or a
		// remote's pin/applied state would be orphaned between runs.
		if again := DirName(remoteName, url); again != name {
			t.Fatalf("DirName(%q, %q) not deterministic: %q != %q", remoteName, url, name, again)
		}

		// Verbatim-or-hash dichotomy: the name is returned verbatim only when
		// it passes the safe-name gate, otherwise it is the url- hash fallback.
		if name == remoteName {
			if !safeName.MatchString(remoteName) {
				t.Fatalf("DirName(%q, %q) returned the name verbatim but it fails the safe-name gate", remoteName, url)
			}
		} else if !strings.HasPrefix(name, "url-") {
			t.Fatalf("DirName(%q, %q) = %q is neither verbatim nor a url- hash fallback", remoteName, url, name)
		}
	})
}

// FuzzCheckPin exercises the rollback-protection decision at the heart of
// cloak's threat model. Once a remote's state is pinned, CheckPin is the gate
// every later fetch passes through: it compares the host-served manifest's
// generation and ciphertext hash against the locally pinned values and must
// reject any remote that did not strictly advance -- a lower generation (a
// rollback/replay), a manifest that changed at the same generation without a
// bump (tamper), or a remote that emptied while a pin exists -- while accepting
// only a true advance or the byte-identical same-generation state. The fixed
// TestCheckPinDecisions pins a handful of transitions; this generalizes the full
// decision contract over arbitrary generations, hash (in)equality, pin presence,
// and the empty-remote case, pinning both the exact alarm taxonomy (Rollback vs
// Tamper) and the one-sided security floor that a pinned remote is never accepted
// unless it strictly advanced or replayed the identical state. CheckPin is the
// host-influenced consumer of two parsed-manifest fields (Generation and the
// ciphertext hash), so this extends the manifest area's integrity contract into
// the rollback gate; the state package previously fuzzed only DirName.
func FuzzCheckPin(f *testing.F) {
	d, err := Open(f.TempDir(), "origin", "u")
	if err != nil {
		f.Fatal(err)
	}

	// firstContact, mPresent, sameHash, pinGen, mGen, hashSeed, mHashSeed
	f.Add(true, true, false, uint64(0), uint64(7), "a", "x")    // TOFU accepts before any pin
	f.Add(false, true, false, uint64(7), uint64(8), "aa", "bb") // higher generation accepted
	f.Add(false, true, true, uint64(7), uint64(7), "aa", "")    // equal generation, same hash accepted
	f.Add(false, true, false, uint64(7), uint64(7), "aa", "bb") // equal generation, different hash -> Tamper
	f.Add(false, true, false, uint64(7), uint64(6), "aa", "bb") // generation regression -> Rollback
	f.Add(false, false, false, uint64(7), uint64(0), "aa", "")  // emptied remote with a pin -> Rollback

	f.Fuzz(func(t *testing.T, firstContact, mPresent, sameHash bool, pinGen, mGen uint64, hashSeed, mHashSeed string) {
		// A pin's ManifestHash round-trips through the "generation" file via
		// fmt.Sscanf("%d %s"), so it must be a single non-empty whitespace-free
		// token to come back byte-identical; deriving it as hex guarantees that
		// while keeping the full hashSeed entropy and not restricting the
		// decision space. The manifest hash (mHash) is passed straight to
		// CheckPin and never written to disk, so it stays an arbitrary
		// host-influenced string -- the real attack surface for the tamper check.
		pinHash := hex.EncodeToString([]byte(hashSeed)) + "0"
		mHash := mHashSeed
		if sameHash {
			mHash = pinHash
		}

		// Establish a known pin state for this iteration. The dir is reused
		// across iterations, so first-contact must actively clear any prior pin.
		if firstContact {
			if err := d.ClearPin(); err != nil {
				t.Fatalf("ClearPin: %v", err)
			}
		} else {
			if err := d.SavePin(Pin{Generation: pinGen, ManifestHash: pinHash}); err != nil {
				t.Fatalf("SavePin: %v", err)
			}
		}

		var m *manifest.Manifest
		if mPresent {
			m = manifest.New()
			m.Generation = mGen
		}

		got := d.CheckPin(m, mHash)

		// Independent oracle: re-derive the expected outcome straight from the
		// inputs, never from CheckPin's body.
		hashEqual := mHash == pinHash
		wantErr := false
		var wantKind cloakerr.Kind
		switch {
		case firstContact:
			// trust-on-first-use: anything accepted before a pin exists.
		case !mPresent:
			wantErr, wantKind = true, cloakerr.Rollback // emptied remote
		case mGen > pinGen:
			// strict advance accepted
		case mGen == pinGen:
			if !hashEqual {
				wantErr, wantKind = true, cloakerr.Tamper // changed without a bump
			}
		default:
			wantErr, wantKind = true, cloakerr.Rollback // generation regression
		}

		if wantErr != (got != nil) {
			t.Fatalf("CheckPin(first=%v present=%v pinGen=%d mGen=%d hashEqual=%v) err=%v, want error=%v",
				firstContact, mPresent, pinGen, mGen, hashEqual, got, wantErr)
		}
		if wantErr {
			if k, _ := cloakerr.KindOf(got); k != wantKind {
				t.Fatalf("CheckPin(first=%v present=%v pinGen=%d mGen=%d hashEqual=%v) kind=%v, want %v (err=%v)",
					firstContact, mPresent, pinGen, mGen, hashEqual, k, wantKind, got)
			}
		}

		// One-sided security floor, stated independently of the taxonomy above:
		// once a pin exists, acceptance REQUIRES the remote to have strictly
		// advanced (mGen > pinGen) or replayed the identical state (mGen == pinGen
		// with the same hash). Any other accepted outcome would let a withholding
		// or rolling-back host slip stale, emptied, or forged state past the gate.
		if !firstContact && got == nil {
			advanced := mPresent && (mGen > pinGen || (mGen == pinGen && hashEqual))
			if !advanced {
				t.Fatalf("CheckPin accepted a non-advancing pinned remote (present=%v pinGen=%d mGen=%d hashEqual=%v)",
					mPresent, pinGen, mGen, hashEqual)
			}
		}

		// Deterministic: re-reading the unchanged pin yields the same verdict.
		if again := d.CheckPin(m, mHash); (again != nil) != (got != nil) {
			t.Fatalf("CheckPin not deterministic: first err=%v second err=%v", got, again)
		}
	})
}

// FuzzCheckRepoID exercises the repository-identity substitution gate, the
// second trust-on-first-use security decision in the state package alongside
// CheckPin. Once a remote's repo identity is pinned, CheckRepoID is the gate
// every later fetch passes through: it compares the host-served manifest's
// RepoID against the locally pinned id and must reject any mismatch as a
// cross-repository substitution (the host served a different repository, or the
// remote points at the wrong URL) with a Tamper alarm, while accepting an exact
// match, an empty remote (no manifest to check), and the first id seen before
// any pin exists. CheckRepoID is the host-influenced consumer of one
// parsed-manifest field (RepoID), so this extends the manifest area's integrity
// contract into the repo-substitution gate. The fixed TestCheckRepoIDDecisions
// pins four transitions; this generalizes the full decision contract over
// arbitrary ids, id (in)equality, pin presence, and the empty-remote case,
// pinning both the alarm classification and its operator-visible "REPO IDENTITY
// MISMATCH" wording (which test/security/repoid_test.go greps to confirm the
// substitution was escalated rather than silently accepted), plus the one-sided
// security floor that a pinned remote carrying a manifest is never accepted
// unless its id matches exactly.
func FuzzCheckRepoID(f *testing.F) {
	d, err := Open(f.TempDir(), "origin", "u")
	if err != nil {
		f.Fatal(err)
	}

	// firstContact, mPresent, sameID, pinSeed, mIDSeed
	f.Add(true, true, false, "a", "x")    // TOFU accepts the first id before any pin
	f.Add(false, false, false, "aa", "")  // empty remote: no manifest, nothing to check
	f.Add(false, true, true, "aa", "")    // matching pinned id accepted
	f.Add(false, true, false, "aa", "bb") // changed id -> substitution Tamper alarm
	f.Add(false, true, false, "", "")     // edge: empty seeds

	f.Fuzz(func(t *testing.T, firstContact, mPresent, sameID bool, pinSeed, mIDSeed string) {
		// The pinned repo id round-trips through the "repoid" state file
		// (SaveRepoID writes id+"\n", LoadRepoID TrimSpace-es it back), so the
		// persisted value must carry no leading/trailing whitespace to come back
		// byte-identical; deriving it as hex guarantees a clean, non-empty token
		// while keeping the full pinSeed entropy. The manifest's RepoID (mID) is
		// passed straight to CheckRepoID and never persisted, so it stays an
		// arbitrary host-influenced string -- the real substitution attack surface.
		pinned := hex.EncodeToString([]byte(pinSeed)) + "0"
		mID := mIDSeed
		if sameID {
			mID = pinned
		}

		// Establish a known pin state for this iteration. The dir is reused
		// across iterations and CheckRepoID never persists, so first-contact must
		// actively clear any prior pin.
		if firstContact {
			if err := d.ClearRepoID(); err != nil {
				t.Fatalf("ClearRepoID: %v", err)
			}
		} else {
			if err := d.SaveRepoID(pinned); err != nil {
				t.Fatalf("SaveRepoID: %v", err)
			}
		}

		var m *manifest.Manifest
		if mPresent {
			m = manifest.New()
			m.RepoID = mID
		}

		got := d.CheckRepoID(m)

		// Independent oracle: re-derive the expected outcome straight from the
		// inputs, never from CheckRepoID's body. The empty-remote case is checked
		// before the pin (m == nil short-circuits in production), so it accepts
		// regardless of whether a pin exists.
		idEqual := mID == pinned
		wantErr := false
		switch {
		case !mPresent:
			// empty remote carries no manifest -> nothing to check
		case firstContact:
			// trust-on-first-use accepts the first id seen
		case idEqual:
			// matching pinned id accepted
		default:
			wantErr = true // substitution -> Tamper alarm
		}

		if wantErr != (got != nil) {
			t.Fatalf("CheckRepoID(first=%v present=%v idEqual=%v) err=%v, want error=%v",
				firstContact, mPresent, idEqual, got, wantErr)
		}
		if wantErr {
			if k, _ := cloakerr.KindOf(got); k != cloakerr.Tamper {
				t.Fatalf("CheckRepoID(first=%v present=%v idEqual=%v) kind=%v, want Tamper (err=%v)",
					firstContact, mPresent, idEqual, k, got)
			}
			// The substitution alarm wording the security suite greps for must
			// survive any host-influenced id; asserted through the real consumer.
			if !strings.Contains(got.Error(), "REPO IDENTITY MISMATCH") {
				t.Fatalf("CheckRepoID mismatch alarm lost its wording: %q", got.Error())
			}
		}

		// One-sided security floor, stated independently of the taxonomy above:
		// once a repo id is pinned and the remote carries a manifest, acceptance
		// REQUIRES an exact id match. Any other accepted outcome would let a host
		// substitute a different repository past the gate.
		if !firstContact && mPresent && got == nil && !idEqual {
			t.Fatalf("CheckRepoID accepted a mismatched pinned repo id (pinned=%q mID=%q)", pinned, mID)
		}

		// Deterministic: CheckRepoID is read-only, so re-reading the unchanged
		// pin yields the same verdict.
		if again := d.CheckRepoID(m); (again != nil) != (got != nil) {
			t.Fatalf("CheckRepoID not deterministic: first err=%v second err=%v", got, again)
		}
	})
}

// FuzzLoadPin exercises the rollback-pin deserializer that feeds CheckPin. Every
// post-pin fetch reads the on-disk "generation" file through LoadPin
// (fmt.Sscanf("%d %s")) to recover the highest accepted generation plus the
// pinned manifest ciphertext hash; CheckPin then trusts those two values to
// reject a rollback/replay/tamper. The existing CheckPin/CheckRepoID fuzzers
// only ever feed pins SavePin itself wrote (well-formed bytes), so the parse of
// arbitrary/corrupt on-disk bytes -- the actual deserialization step -- had no
// coverage. This pins two contracts over arbitrary file content plus an
// independent valid Pin: (1) fail-closed, LoadPin never panics and never
// reports a usable pin (ok && nil err) without having extracted both a
// generation and a non-empty whitespace-free hash, so a truncated/garbage file
// can never be accepted as a zero-generation pin that would silently defeat the
// rollback check; and (2) round-trip faithfulness, any Pin SavePin persists
// LoadPin recovers byte-identically. The hash must be a clean, non-empty,
// whitespace-free token to survive the "%d %s" codec, which hex guarantees.
func FuzzLoadPin(f *testing.F) {
	d, err := Open(f.TempDir(), "origin", "u")
	if err != nil {
		f.Fatal(err)
	}
	pinPath := filepath.Join(d.Root, pinFile)

	// raw on-disk bytes, plus a valid (gen, hashSeed) for the round-trip.
	f.Add([]byte("7 abcdef\n"), uint64(7), "abcdef")                             // the honest shape SavePin writes
	f.Add([]byte(""), uint64(0), "")                                             // empty file -> corrupt
	f.Add([]byte("notanumber"), uint64(1), "x")                                  // no leading integer
	f.Add([]byte("5"), uint64(5), "deadbeef")                                    // generation only, no hash token
	f.Add([]byte("5 "), uint64(5), "deadbeef")                                   // generation + trailing space, no hash
	f.Add([]byte("  9   hash  \n"), uint64(9), "hash")                           // surrounding/inner whitespace
	f.Add([]byte("18446744073709551615 ff"), uint64(18446744073709551615), "ff") // max uint64 boundary
	f.Add([]byte("-1 ff"), uint64(0), "ff")                                      // negative rejected by %d into uint64
	f.Add([]byte("3 a b c"), uint64(3), "a")                                     // extra trailing tokens after the hash

	f.Fuzz(func(t *testing.T, raw []byte, gen uint64, hashSeed string) {
		// --- Arbitrary-bytes path: parse whatever bytes are on disk. ---
		if err := os.WriteFile(pinPath, raw, 0o600); err != nil {
			t.Fatalf("write pin file: %v", err)
		}
		p, ok, err := d.LoadPin()

		// The file definitely exists (we just wrote it), so ok==false must be
		// paired with a parse error, and ok==true with a clean parse. A
		// successful parse must have extracted a non-empty, whitespace-free
		// hash: Sscanf "%d %s" cannot succeed without both a generation and a
		// hash token, so a corrupt/truncated file is never accepted as a
		// zero-generation pin that would slip a rollback past CheckPin.
		switch {
		case err != nil:
			if ok {
				t.Fatalf("LoadPin(%q) returned ok alongside an error: %v", raw, err)
			}
		case ok:
			if p.ManifestHash == "" {
				t.Fatalf("LoadPin(%q) accepted a pin with an empty hash: %+v", raw, p)
			}
			if strings.ContainsAny(p.ManifestHash, " \t\r\n") {
				t.Fatalf("LoadPin(%q) accepted a hash carrying whitespace: %q", raw, p.ManifestHash)
			}
		default:
			t.Fatalf("LoadPin(%q) reported no record though the file exists", raw)
		}

		// Deterministic: re-reading the unchanged bytes yields the same verdict.
		if p2, ok2, err2 := d.LoadPin(); ok2 != ok || (err2 != nil) != (err != nil) || p2 != p {
			t.Fatalf("LoadPin(%q) not deterministic: (%+v,%v,%v) vs (%+v,%v,%v)",
				raw, p, ok, err, p2, ok2, err2)
		}

		// --- Round-trip path: any Pin SavePin persists must LoadPin back
		// byte-identically. The hash is derived as hex so it is a clean,
		// non-empty, whitespace-free token the "%d %s" codec round-trips. ---
		want := Pin{Generation: gen, ManifestHash: hex.EncodeToString([]byte(hashSeed)) + "0"}
		if err := d.SavePin(want); err != nil {
			t.Fatalf("SavePin(%+v): %v", want, err)
		}
		got, ok, err := d.LoadPin()
		if err != nil || !ok {
			t.Fatalf("LoadPin after SavePin(%+v): ok=%v err=%v", want, ok, err)
		}
		if got != want {
			t.Fatalf("pin round-trip mismatch: saved %+v, loaded %+v", want, got)
		}
	})
}

// FuzzAppliedSet exercises the applied-pack-set parser and its MarkApplied
// round-trip. AppliedSet reads the on-disk "applied" file into the set of pack
// ids the local repo has already indexed; downloadUnlessSkippable consults that
// set (via packSkippable, fuzzed in engine.FuzzPackSkippable) to decide whether a
// manifest pack can be skipped, so the set must faithfully reflect exactly the
// ids MarkApplied wrote -- never fabricating or mangling one, since an
// over-reported id could let a pack that supersedes it be wrongly skipped and
// leave the local repo missing objects. The single fixed TestAppliedSet pins one
// "p1","p2","p3" sequence; this generalizes two contracts: (1) robustness +
// faithfulness, over arbitrary on-disk bytes AppliedSet never errors and returns
// exactly the trimmed, non-empty newline-delimited lines (no fabrication, no
// dropped line, no empty id), and (2) round-trip, any clean ids MarkApplied
// persists across one or more calls AppliedSet recovers as their de-duplicated
// set. The "applied" file is created and only ever appended to by MarkApplied
// (one "<id>\n" per id), so AppliedSet is its sole reader.
func FuzzAppliedSet(f *testing.F) {
	d, err := Open(f.TempDir(), "origin", "u")
	if err != nil {
		f.Fatal(err)
	}
	appliedPath := filepath.Join(d.Root, appliedFile)

	// raw on-disk bytes, plus a seed for the round-trip ids.
	f.Add([]byte("p1\np2\np3\n"), "p1")         // the honest shape MarkApplied writes
	f.Add([]byte(""), "")                       // empty file -> empty set
	f.Add([]byte("\n\n\n"), "x")                // only blank lines -> empty set
	f.Add([]byte("  spaced  \n\tabc\t\n"), "y") // surrounding whitespace trimmed off
	f.Add([]byte("a\r\nb"), "z")                // CRLF plus a final unterminated line
	f.Add([]byte("dup\ndup\n"), "w")            // duplicate lines collapse in the set
	f.Add([]byte("a b c\n"), "v")               // internal whitespace kept (one id)

	f.Fuzz(func(t *testing.T, raw []byte, idSeed string) {
		// --- Arbitrary-bytes path: parse whatever bytes are on disk. ---
		if err := os.WriteFile(appliedPath, raw, 0o600); err != nil {
			t.Fatalf("write applied file: %v", err)
		}
		got, err := d.AppliedSet()
		// Robustness: the parse (split + trim + skip-empty) cannot fail, so
		// arbitrary bytes never produce an error.
		if err != nil {
			t.Fatalf("AppliedSet(%q) errored on arbitrary bytes: %v", raw, err)
		}

		// Independent oracle via a genuinely different splitter: strings.FieldsFunc
		// on '\n' (which drops empty fields outright) is provably equivalent to the
		// implementation's strings.Split + per-line TrimSpace + skip-empty, because
		// '\n' is ASCII (never a UTF-8 continuation byte, so both split at the same
		// byte offsets even on invalid UTF-8) and an empty Split segment trims to ""
		// and is skipped just as FieldsFunc would have dropped it. maps.Equal then
		// pins that every reported id is a trimmed non-empty line actually present
		// (no fabrication), no line is dropped, and no empty id is ever a member.
		want := map[string]bool{}
		for _, fld := range strings.FieldsFunc(string(raw), func(r rune) bool { return r == '\n' }) {
			if tr := strings.TrimSpace(fld); tr != "" {
				want[tr] = true
			}
		}
		if !maps.Equal(got, want) {
			t.Fatalf("AppliedSet(%q) = %v, want %v", raw, got, want)
		}

		// Deterministic: re-reading the unchanged bytes yields an equal set.
		if again, err := d.AppliedSet(); err != nil || !maps.Equal(again, got) {
			t.Fatalf("AppliedSet(%q) not deterministic: %v (err=%v) vs %v", raw, again, err, got)
		}

		// --- Round-trip path: clear the file and exercise MarkApplied's
		// create+append from scratch, exactly as production grows the applied set
		// over successive fetches. The ids are derived as hex so they are clean,
		// non-empty, whitespace-free tokens that survive the "<id>\n" round-trip
		// byte-identically. ---
		if err := os.Remove(appliedPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("reset applied file: %v", err)
		}
		id1 := hex.EncodeToString([]byte(idSeed)) + "0" // clean, non-empty
		id2 := id1 + "1"                                // a distinct clean id
		if err := d.MarkApplied(id1, id2); err != nil {
			t.Fatalf("MarkApplied(%q,%q): %v", id1, id2, err)
		}
		// A repeat mark is set-idempotent: the file grows by another line but the
		// parsed set is unchanged, since packSkippable consumes a SET not a count.
		if err := d.MarkApplied(id1); err != nil {
			t.Fatalf("MarkApplied repeat: %v", err)
		}
		rt, err := d.AppliedSet()
		if err != nil {
			t.Fatalf("AppliedSet after MarkApplied: %v", err)
		}
		if wantRT := (map[string]bool{id1: true, id2: true}); !maps.Equal(rt, wantRT) {
			t.Fatalf("applied round-trip mismatch: marked %v, got %v", wantRT, rt)
		}
	})
}
