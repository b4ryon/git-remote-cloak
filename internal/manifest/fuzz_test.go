// Fuzz tests for the manifest codec. Decode parses the decrypted manifest
// plaintext, which originates on the (untrusted) remote, so it must never
// panic on arbitrary bytes. Beyond that, any input Decode is willing to accept
// must survive a Decode -> Encode -> Decode -> Encode cycle reproducing the
// same bytes: a manifest this build reads must be one it can faithfully
// re-emit and re-read. FuzzCloneIsolation additionally pins Clone's deep-copy
// contract, since the engine clones the cached manifest and mutates the copy
// on every push and repack. FuzzEncodeRoundTrip drives the opposite (write)
// direction: it Encodes hand-built Manifest structs, the way the engine
// assembles new remote state, and pins that anything Encode emits is faithfully
// re-readable and byte-stable. FuzzValidatePackSet drills into the deepest part
// of that write path -- the cross-pack validation matrix (duplicate ids and the
// live-vs-replaces disjointness check) that FuzzEncodeRoundTrip's fixed two-pack
// shape barely reaches -- by building arbitrary-cardinality pack sets from a
// small id pool and pinning Validate's exact accept/reject contract.
// FuzzValidateMeta is its sibling: it pins Validate's META phase (the version,
// repo-id, and head checks) with the same bidirectional accept/reject oracle,
// the one validation phase FuzzValidatePackSet holds fixed and FuzzEncodeRoundTrip
// only round-trips on the accept side. FuzzValidateRefs completes the trio,
// pinning Validate's REFS phase -- every ref name is under refs/, valid UTF-8,
// and advertisement-safe, and every target is a well-formed 40-hex object id --
// with the same bidirectional oracle over a two-ref map, so it also exercises the
// per-ref conjunction (one bad ref rejects the whole manifest) and the
// map-iteration-order independence of the accept/reject decision that a single
// fixed ref never reaches. FuzzValidatePackIDs completes the pack phase as the
// symmetric complement of FuzzValidatePackSet: where that target fuzzes the
// cross-pack structure with well-formed pool ids, this one fuzzes arbitrary id
// strings for a single pack and its Replaces, pinning the malformed-pack-id and
// malformed-Replaces-id rejection branches -- the per-id well-formedness sub-gate
// that the pool-id structural target deliberately never reaches and that
// FuzzEncodeRoundTrip executes but never bidirectionally pins (it returns early on
// rejection without checking the rejection was warranted). FuzzRejectsUnknownField covers a separate Decode
// guard the above never touch: DisallowUnknownFields, the anti-smuggling gate
// that rejects any field outside the schema so a hostile remote cannot hide data
// in fields this build ignores. It injects an arbitrary unknown field into an
// otherwise-valid manifest at either the top level or the nested pack object
// (Go's DisallowUnknownFields recurses), generalizing the single fixed unit case.
// FuzzValidatePackCount closes the last pack-phase rejection cause none of the
// above reach: the len(m.Packs) > maxPacks count cap, which the pool/single-pack
// fuzzers bound far below maxPacks and so never exercise. It builds pack lists
// straddling the cap and pins both the boundary and the ordering invariant the
// TestPackCountCap unit test omits -- the count check fires before any per-pack
// check, so an over-count manifest is rejected with the count-cap error even when
// it also carries a duplicate/over-cap-size/malformed-id pack.
// FuzzDecodeTrailingData covers a second Decode guard alongside
// FuzzRejectsUnknownField: json.Decoder.Decode reads only the first JSON value
// and silently ignores anything after it, so it pins that Decode rejects any
// non-whitespace bytes appended past the manifest object (a second object or
// arbitrary bytes a keyed party could otherwise smuggle past this build) while
// still tolerating trailing JSON whitespace exactly as json.Unmarshal does.
package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzDecode(f *testing.F) {
	// A fully populated valid manifest, the minimal valid manifest, and the
	// rejection edges the unit tests already cover.
	f.Add([]byte(`{"version":1,"repo_id":"0123456789abcdef0123456789abcdef","generation":41,"head":"refs/heads/main","refs":{"refs/heads/main":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"packs":[{"id":"1111111111111111111111111111111111111111111111111111111111111111","size":1234,"replaces":["2222222222222222222222222222222222222222222222222222222222222222"]}]}`))
	f.Add([]byte(`{"version":1,"repo_id":"0123456789abcdef0123456789abcdef","generation":0,"refs":{},"packs":[]}`))
	f.Add([]byte(`{"version":7}`))
	f.Add([]byte("not json"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Decode(data)
		if err != nil {
			return // a rejected input is fine; the requirement is no panic
		}
		// Decode validated m, so Encode (which re-validates) must accept it.
		enc, err := Encode(m)
		if err != nil {
			t.Fatalf("Decode accepted a manifest that Encode rejected: %v", err)
		}
		// enc is canonical JSON; re-reading and re-emitting it must be stable.
		m2, err := Decode(enc)
		if err != nil {
			t.Fatalf("re-Decode of encoded manifest failed: %v", err)
		}
		enc2, err := Encode(m2)
		if err != nil {
			t.Fatalf("re-Encode of round-tripped manifest failed: %v", err)
		}
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("round trip not stable:\n first: %s\nsecond: %s", enc, enc2)
		}
	})
}

// FuzzCloneIsolation locks down Clone's deep-copy contract. The engine clones
// the cached remote manifest and then mutates the copy on every push and
// repack (engine/push.go assembleManifest, engine/consolidate.go), so a Clone
// that aliased its source's Refs map or any Pack's Replaces slice would let an
// in-flight push silently corrupt the cached source state and emit a wrong
// manifest. For any manifest Decode accepts: the clone must re-Encode to the
// same bytes (a faithful copy), and mutating every reference-typed field of the
// clone in place must leave the source's encoding byte-for-byte unchanged (full
// isolation, i.e. no shared backing storage).
func FuzzCloneIsolation(f *testing.F) {
	// A manifest exercising every reference-typed field (multi-entry refs,
	// multiple packs, a populated Replaces) plus the minimal empty shape.
	f.Add([]byte(`{"version":1,"repo_id":"0123456789abcdef0123456789abcdef","generation":41,"head":"refs/heads/main","refs":{"refs/heads/main":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","refs/heads/dev":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"packs":[{"id":"1111111111111111111111111111111111111111111111111111111111111111","size":1234,"replaces":["2222222222222222222222222222222222222222222222222222222222222222","3333333333333333333333333333333333333333333333333333333333333333"]},{"id":"4444444444444444444444444444444444444444444444444444444444444444","size":7}]}`))
	f.Add([]byte(`{"version":1,"repo_id":"0123456789abcdef0123456789abcdef","generation":0,"refs":{},"packs":[]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Decode(data)
		if err != nil {
			return // only well-formed manifests reach Clone in production
		}
		// Snapshot the source's canonical bytes before cloning. Encode is
		// deterministic (json sorts map keys), so this is m's stable identity.
		enc0, err := Encode(m)
		if err != nil {
			t.Fatalf("Decode accepted a manifest that Encode rejected: %v", err)
		}

		c := m.Clone()

		// Fidelity: the clone must carry every field unchanged.
		encClone, err := Encode(c)
		if err != nil {
			t.Fatalf("clone of an accepted manifest failed to Encode: %v", err)
		}
		if !bytes.Equal(enc0, encClone) {
			t.Fatalf("Clone did not reproduce the manifest:\n source: %s\n clone:  %s", enc0, encClone)
		}

		// Isolation: scribble over every reference-typed field of the clone in
		// place. The clone is never re-validated or re-encoded, so the marker
		// values need not be well-formed. If any structure were shared with the
		// source, one of these writes would bleed back into m.
		c.Version = m.Version + 1
		c.Generation++
		c.RepoID = "MUTATED"
		c.Head = "MUTATED"
		c.Refs["refs/heads/__mutated__"] = "MUTATED" // add (reveals map aliasing)
		for k := range c.Refs {
			c.Refs[k] = "MUTATED" // overwrite existing values
		}
		for i := range c.Packs {
			c.Packs[i].ID = "MUTATED"
			c.Packs[i].Size++
			for j := range c.Packs[i].Replaces {
				c.Packs[i].Replaces[j] = "MUTATED" // in-place: reveals slice aliasing
			}
		}
		c.Packs = append(c.Packs, Pack{ID: "MUTATED"})

		// The source must be untouched: re-encoding it still yields enc0.
		enc1, err := Encode(m)
		if err != nil {
			t.Fatalf("source manifest no longer Encodes after mutating its clone: %v", err)
		}
		if !bytes.Equal(enc0, enc1) {
			t.Fatalf("mutating the clone corrupted its source:\n before: %s\n after:  %s", enc0, enc1)
		}
	})
}

// FuzzEncodeRoundTrip fuzzes the manifest WRITE path. The engine never Decodes
// the manifests it stores: it builds them in memory (manifest.New / Clone plus
// mutations) and calls Encode (engine/push.go assembleManifest,
// engine/consolidate.go), which validates the hand-built struct and marshals
// it. Every other manifest fuzz test enters through Decode, so the deep
// validation branches Encode relies on -- the pack-count and per-pack size
// caps, duplicate pack ids, and the Replaces cross-check that no Replaces id
// names a still-live pack -- are reached only when FuzzDecode manages to
// synthesize valid JSON, which it rarely does. Building the struct directly
// drives those branches efficiently. The pinned invariant is the property the
// on-remote manifest depends on: anything this build Encodes must Decode back
// (Encode and Decode agree on validity), and re-Encoding the decoded result
// must reproduce the same bytes (the write output is canonical and stable).
//
// Refs is always a non-nil map because the engine never produces a nil Refs
// (New seeds it to {} and Clone copies it via make); a nil Refs is the one
// shape whose write round trip is intentionally lossy ("refs":null is
// normalized to {} on Decode), and it is unreachable in honest operation.
func FuzzEncodeRoundTrip(f *testing.F) {
	const (
		id32 = "0123456789abcdef0123456789abcdef"                                 // valid repo id
		oid  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"                         // valid 40-hex object id
		p1   = "1111111111111111111111111111111111111111111111111111111111111111" // valid 64-hex pack id
		p4   = "4444444444444444444444444444444444444444444444444444444444444444"
		p2   = "2222222222222222222222222222222222222222222222222222222222222222"
	)
	// A fully populated valid manifest (two distinct packs, p0 replacing a
	// non-live pack), the minimal valid shape, and the three rejection edges
	// that exercise the deep validators: duplicate pack id, Replaces naming a
	// live pack, and an unsupported version.
	f.Add(1, id32, uint64(41), "refs/heads/main", "refs/heads/main", oid, p1, int64(1234), p4, int64(7), p2)
	f.Add(1, id32, uint64(0), "", "", "", "", int64(0), "", int64(0), "")
	f.Add(1, id32, uint64(0), "", "", "", p1, int64(1), p1, int64(2), "") // duplicate pack id
	f.Add(1, id32, uint64(0), "", "", "", p1, int64(1), p4, int64(2), p4) // p0 replaces live pack p4
	f.Add(7, id32, uint64(0), "", "", "", "", int64(0), "", int64(0), "") // unsupported version

	f.Fuzz(func(t *testing.T, version int, repoID string, generation uint64, head string,
		refName, refOID string, p0ID string, p0Size int64, p1ID string, p1Size int64, replaceID string) {
		m := &Manifest{
			Version:    version,
			RepoID:     repoID,
			Generation: generation,
			Head:       head,
			Refs:       map[string]string{},
		}
		if refName != "" {
			m.Refs[refName] = refOID
		}
		if p0ID != "" {
			p := Pack{ID: p0ID, Size: p0Size}
			if replaceID != "" {
				p.Replaces = []string{replaceID}
			}
			m.Packs = append(m.Packs, p)
		}
		if p1ID != "" {
			m.Packs = append(m.Packs, Pack{ID: p1ID, Size: p1Size})
		}

		enc, err := Encode(m)
		if err != nil {
			return // Validate rejected the hand-built manifest: fine, no panic
		}
		// Encode and Decode share one Validate, and Encode emits only known
		// fields with a non-nil Refs, so anything Encode accepts Decode must too.
		m2, err := Decode(enc)
		if err != nil {
			t.Fatalf("Encode produced output Decode rejected: %v\n%s", err, enc)
		}
		// Encode is canonical (json sorts map keys); re-emitting the decoded
		// manifest must reproduce the exact same bytes.
		enc2, err := Encode(m2)
		if err != nil {
			t.Fatalf("re-Encode of round-tripped manifest failed: %v", err)
		}
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("write round trip not stable:\n first: %s\nsecond: %s", enc, enc2)
		}
	})
}

// packPool is a small set of distinct, well-formed (64-hex) pack ids. Drawing
// both pack ids AND Replaces ids from this tiny pool is what makes the
// duplicate-id and live-vs-replaces collisions frequent: with random 64-hex ids
// those rejection branches are effectively unreachable (two random ids never
// match), so FuzzEncodeRoundTrip almost never drives them. A shared pool turns
// every fuzzed pack list into a dense exercise of the cross-pack matrix.
var packPool = []string{
	strings.Repeat("0", 64),
	strings.Repeat("1", 64),
	strings.Repeat("2", 64),
	strings.Repeat("3", 64),
	strings.Repeat("4", 64),
	strings.Repeat("5", 64),
}

// packsFromFuzz deterministically decodes fuzz bytes into a pack list. Each pack
// consumes up to: 1 byte selecting its id from packPool, 1 byte selecting a size
// MODE, 2 bytes of size magnitude, 1 byte for a replace count (0..4), and that
// many bytes each selecting a Replaces id from packPool. The four size modes
// deterministically reach both the in-range and the negative/over-cap rejection
// branches of validatePack, which raw 8-byte sizes (almost always > maxPackSize)
// never would. Decoding stops at end-of-input or maxFuzzPacks, so the list is
// always bounded.
func packsFromFuzz(data []byte) []Pack {
	const maxFuzzPacks = 64
	var packs []Pack
	i := 0
	rd := func() (byte, bool) {
		if i >= len(data) {
			return 0, false
		}
		b := data[i]
		i++
		return b, true
	}
	for len(packs) < maxFuzzPacks {
		idb, ok := rd()
		if !ok {
			break // out of input: stop adding packs
		}
		p := Pack{ID: packPool[int(idb)%len(packPool)]}
		mode, _ := rd()
		lo, _ := rd()
		hi, _ := rd()
		v := int64(lo) | int64(hi)<<8 // 0..65535 magnitude
		switch mode % 4 {
		case 0:
			p.Size = v // small, in range
		case 1:
			p.Size = maxPackSize // boundary, in range
		case 2:
			p.Size = maxPackSize + 1 + v // over the cap
		case 3:
			p.Size = -v - 1 // negative
		}
		rcb, _ := rd()
		for k := 0; k < int(rcb%5); k++ {
			rb, ok := rd()
			if !ok {
				break
			}
			p.Replaces = append(p.Replaces, packPool[int(rb)%len(packPool)])
		}
		packs = append(packs, p)
	}
	return packs
}

// FuzzValidatePackSet pins Validate's full accept/reject contract over the pack
// list, the part of the manifest schema the rest of cloak trusts blindly:
// geometry's consolidation planner (internal/geometry), the engine's pack-skip
// gate (packSkippable/replacesCovered), and the status command all ASSUME a
// validated manifest has unique live pack ids that are disjoint from every
// Replaces id and sizes within [0, maxPackSize]. With the meta and refs held
// valid, Validate accepts a pack list IFF none of those invariants is violated;
// this re-derives the violation set independently (via set intersection rather
// than the validator's single-pass seen map) and asserts the biconditional, so
// it catches BOTH a false rejection (which would break an honest push) and a
// false acceptance (which would let a malformed manifest reach those consumers).
// Accepted manifests are additionally held to the byte-stable Decode/Encode
// round trip, generalizing FuzzEncodeRoundTrip to arbitrary pack cardinality.
func FuzzValidatePackSet(f *testing.F) {
	f.Add([]byte{})                                // no packs
	f.Add([]byte{0})                               // one in-range pack
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})    // two id0 packs: duplicate
	f.Add([]byte{0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0}) // id0 replaces live id1: overlap
	f.Add([]byte{0, 2, 0, 0, 0})                   // over-cap size
	f.Add([]byte{0, 3, 0, 0, 0})                   // negative size
	f.Add([]byte{0, 0, 5, 0, 1, 3, 1, 0, 7, 0, 0}) // id0 (replaces dead id3) + id1: accepted
	f.Add([]byte{0, 1, 0, 0, 0})                   // boundary size == maxPackSize

	f.Fuzz(func(t *testing.T, data []byte) {
		packs := packsFromFuzz(data)
		m := &Manifest{
			Version:    Version,
			RepoID:     repoID, // valid 32-hex from manifest_test.go
			Generation: 1,
			Refs:       map[string]string{},
			Packs:      packs,
		}

		v := derivePackSetVerdict(packs)

		enc, err := Encode(m)
		if (err != nil) != v.reject {
			if err != nil {
				t.Fatalf("Validate rejected a pack set with no invariant violation "+
					"(dup=%v sizeBad=%v overlap=%v count=%d): %v", v.dup, v.sizeBad, v.overlap, v.count, err)
			}
			t.Fatalf("Validate ACCEPTED a pack set that violates an invariant "+
				"(dup=%v sizeBad=%v overlap=%v count=%d)", v.dup, v.sizeBad, v.overlap, v.count)
		}
		if err != nil {
			return // correctly rejected
		}

		// Accepted: the canonical bytes must Decode back and re-Encode identically.
		assertPackSetRoundTrip(t, enc)
	})
}

// packSetVerdict is the independently re-derived expectation for whether
// Validate must reject a pack set, plus the individual violation flags used to
// describe a mismatch.
type packSetVerdict struct {
	dup, sizeBad, overlap bool
	count                 int
	reject                bool
}

// derivePackSetVerdict re-derives, independently of validatePacks/
// validateReplaces, whether the pack set violates any invariant Validate
// enforces. Pack ids and Replaces ids are always well-formed (pool entries),
// and meta+refs are valid, so these are the ONLY reasons Validate can reject.
// The set-intersection decomposition here is deliberately different from the
// validator's single-pass seen map, so the oracle catches drift rather than
// mirroring it.
func derivePackSetVerdict(packs []Pack) packSetVerdict {
	live := map[string]int{}
	for _, p := range packs {
		live[p.ID]++
	}
	var v packSetVerdict
	liveSet := map[string]bool{}
	for id, n := range live {
		liveSet[id] = true
		if n > 1 {
			v.dup = true
		}
	}
	for _, p := range packs {
		if p.Size < 0 || p.Size > maxPackSize {
			v.sizeBad = true
		}
	}
	for _, p := range packs {
		for _, r := range p.Replaces {
			if liveSet[r] {
				v.overlap = true
			}
		}
	}
	v.count = len(packs)
	// count > maxPacks is unreachable here (packsFromFuzz caps the list), kept
	// for completeness.
	v.reject = v.dup || v.sizeBad || v.overlap || v.count > maxPacks
	return v
}

// assertPackSetRoundTrip holds an accepted manifest's canonical bytes to the
// byte-stable Decode/Encode round trip, generalizing FuzzEncodeRoundTrip to
// arbitrary pack cardinality.
func assertPackSetRoundTrip(t *testing.T, enc []byte) {
	t.Helper()
	m2, err := Decode(enc)
	if err != nil {
		t.Fatalf("Encode produced output Decode rejected: %v\n%s", err, enc)
	}
	enc2, err := Encode(m2)
	if err != nil {
		t.Fatalf("re-Encode of round-tripped manifest failed: %v", err)
	}
	if !bytes.Equal(enc, enc2) {
		t.Fatalf("pack-set round trip not stable:\n first: %s\nsecond: %s", enc, enc2)
	}
}

// metaRepoID builds a repo id that reaches both sides of validateMeta's repo-id
// gate: a guaranteed-valid 32-hex id (mode 0), an arbitrary string (mode 1,
// almost always rejected), the empty/missing case (mode 2, the v0-style absence
// the gate exists to reject), and a valid-charset-but-wrong-length near-miss
// (mode 3) that exercises the repo-id length check (IsLowerHex(_, 32)).
func metaRepoID(mode uint8, raw string) string {
	switch mode % 4 {
	case 0:
		return validRepoHex(raw)
	case 1:
		return raw
	case 2:
		return ""
	default:
		return validRepoHex(raw)[:31] // 31 hex chars: right charset, wrong length
	}
}

// validRepoHex returns exactly 32 lowercase hex chars derived from raw
// (zero-padded/truncated to 16 bytes), so it always satisfies the repo-id check.
func validRepoHex(raw string) string {
	b := make([]byte, 16)
	copy(b, raw)
	return hex.EncodeToString(b)
}

// metaHead builds a head that reaches both sides of validateMeta's head gate:
// the empty/no-head case (mode 0), a refs/heads/-prefixed branch whose validity
// then turns on raw's UTF-8/advert-safety (mode 1), an arbitrary non-prefixed
// value (mode 2, almost always rejected), and a fixed valid branch (mode 3).
func metaHead(mode uint8, raw string) string {
	switch mode % 4 {
	case 0:
		return ""
	case 1:
		return "refs/heads/" + raw
	case 2:
		return raw
	default:
		return "refs/heads/main"
	}
}

// isHexLen reports whether s is exactly n lowercase hex chars. It is an
// independently written restatement of the production check (manifest's
// IsLowerHex(_, n), i.e. ^[0-9a-f]{n}$), deliberately kept as a separate
// hand-written copy -- NOT a call to IsLowerHex -- so the oracle catches a drift
// in that production check rather than reusing (and so mirroring) its code. The
// per-caller length is pinned at each call site: 32 for the repo-id, 40 for an
// object-id, 64 for a pack-id.
func isHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// metaHeadValid independently restates validateMeta's head contract: empty, or a
// refs/heads/-prefixed valid-UTF-8 string carrying no ASCII control char or space
// (the bytes the helper's "@<head> HEAD" advertisement line cannot safely carry).
func metaHeadValid(h string) bool {
	if h == "" {
		return true
	}
	if !strings.HasPrefix(h, "refs/heads/") {
		return false
	}
	if !utf8.ValidString(h) {
		return false
	}
	for i := 0; i < len(h); i++ {
		if h[i] <= ' ' || h[i] == 0x7f {
			return false
		}
	}
	return true
}

// FuzzValidateMeta pins Validate's META phase -- the version, repo-id, and head
// checks (validateMeta) -- with a bidirectional accept/reject contract, the
// counterpart to FuzzValidatePackSet's pack-phase coverage. The other manifest
// fuzzers leave this phase under-pinned: FuzzEncodeRoundTrip varies version,
// repo id, and head but only checks round-trip stability on ACCEPTED manifests
// (it returns early without checking that a REJECTION was warranted), so a false
// acceptance here would slip past it. validateMeta guards three properties cloak
// depends on: only this build's schema version is read (a host cannot downgrade a
// client to a v0 manifest predating repo-id binding), the manifest carries a
// well-formed RepoID (the identity CheckRepoID compares to reject a substituted
// repository), and the head is valid UTF-8 (JSON cannot faithfully store
// non-UTF-8, so an invalid-UTF-8 head must fail closed rather than be silently
// coerced to U+FFFD) and advertisement-safe (no control char or space the
// "@<head> HEAD" line would inject into git's protocol stream). With refs empty
// and packs nil (both trivially valid), validateMeta is the ONLY possible
// rejection cause, so Encode accepts IFF the meta is valid; the oracle re-derives
// validity independently and asserts the biconditional, catching both a false
// rejection (which would break an honest push) and a false acceptance (which
// would let a downgraded/unbound/injection-bearing manifest through).
func FuzzValidateMeta(f *testing.F) {
	f.Add(true, 0, uint8(0), "", uint8(0), "")               // v1, derived repo id, no head: accept
	f.Add(true, 0, uint8(0), "seed", uint8(3), "")           // v1, derived repo id, refs/heads/main: accept
	f.Add(false, 0, uint8(0), "", uint8(0), "")              // version 0 (the v0 downgrade the gate rejects)
	f.Add(false, 7, uint8(0), "", uint8(0), "")              // future version 7: reject
	f.Add(true, 0, uint8(2), "", uint8(0), "")               // missing repo id: reject
	f.Add(true, 0, uint8(3), "", uint8(0), "")               // 31-hex repo id (wrong length): reject
	f.Add(true, 0, uint8(1), "not-hex", uint8(0), "")        // arbitrary repo id: reject
	f.Add(true, 0, uint8(0), "seed", uint8(2), "not-branch") // head without refs/heads/ prefix: reject
	f.Add(true, 0, uint8(0), "seed", uint8(1), "main\n")     // head with embedded newline (advert-unsafe): reject
	f.Add(true, 0, uint8(0), "seed", uint8(1), "\xff")       // head with invalid UTF-8 (JSON-faithfulness guard): reject

	f.Fuzz(func(t *testing.T, verValid bool, verRaw int, repoMode uint8, repoRaw string,
		headMode uint8, headRaw string) {
		version := verRaw
		if verValid {
			version = Version
		}
		rid := metaRepoID(repoMode, repoRaw)
		head := metaHead(headMode, headRaw)

		m := &Manifest{
			Version:    version,
			RepoID:     rid,
			Generation: 1,
			Head:       head,
			Refs:       map[string]string{}, // empty: trivially valid
			// Packs nil: trivially valid, so validateMeta is the only rejecter.
		}

		// Independently re-derive meta validity. isHexLen(_, 32) is a length+byte-loop
		// restatement of the repo-id check (IsLowerHex(_, 32)), and metaHeadValid
		// restates the head contract; with refs empty and packs nil these are the
		// exact and only conditions under which Validate (hence Encode) accepts.
		metaOK := version == Version && isHexLen(rid, 32) && metaHeadValid(head)

		enc, err := Encode(m)
		if (err != nil) == metaOK {
			if err != nil {
				t.Fatalf("Validate rejected valid meta (version=%d repoID=%q head=%q): %v",
					version, rid, head, err)
			}
			t.Fatalf("Validate ACCEPTED invalid meta (version=%d repoID=%q head=%q)",
				version, rid, head)
		}
		if err != nil {
			return // correctly rejected
		}

		// Accepted: the canonical bytes must Decode back and re-Encode identically.
		m2, err := Decode(enc)
		if err != nil {
			t.Fatalf("Encode produced output Decode rejected: %v\n%s", err, enc)
		}
		enc2, err := Encode(m2)
		if err != nil {
			t.Fatalf("re-Encode of round-tripped manifest failed: %v", err)
		}
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("meta round trip not stable:\n first: %s\nsecond: %s", enc, enc2)
		}
	})
}

// refName builds a ref name reaching both sides of validateRefs's name gate: a
// refs/-prefixed name whose validity then turns on raw's UTF-8/advert-safety
// (mode 0), an arbitrary non-prefixed string (mode 1, almost always rejected for
// lacking the refs/ prefix), a fixed valid name (mode 2), and a refs/heads/-
// prefixed name (mode 3, the same prefix-valid-then-raw-dependent shape under the
// common heads/ namespace).
func refName(mode uint8, raw string) string {
	switch mode % 4 {
	case 0:
		return "refs/" + raw
	case 1:
		return raw
	case 2:
		return "refs/heads/main"
	default:
		return "refs/heads/" + raw
	}
}

// refOID builds an object id reaching both sides of validateRefs's oid gate: a
// guaranteed-valid 40-hex id derived from raw (mode 0), an arbitrary string
// (mode 1, almost always rejected), and a valid-charset-but-wrong-length
// near-miss (mode 2) that exercises the object-id length check (IsLowerHex(_, 40)).
func refOID(mode uint8, raw string) string {
	switch mode % 3 {
	case 0:
		return validOIDHex(raw)
	case 1:
		return raw
	default:
		return validOIDHex(raw)[:39] // 39 hex chars: right charset, wrong length
	}
}

// validOIDHex returns exactly 40 lowercase hex chars derived from raw
// (zero-padded/truncated to 20 bytes), so it always satisfies the object-id check.
func validOIDHex(raw string) string {
	b := make([]byte, 20)
	copy(b, raw)
	return hex.EncodeToString(b)
}

// refNameValid independently restates validateRefs's name contract: under refs/,
// valid UTF-8, and carrying no ASCII control char or space (the bytes the
// helper's "<oid> <name>" advertisement line cannot safely carry).
func refNameValid(name string) bool {
	if !strings.HasPrefix(name, "refs/") {
		return false
	}
	if !utf8.ValidString(name) {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] <= ' ' || name[i] == 0x7f {
			return false
		}
	}
	return true
}

// FuzzValidateRefs pins Validate's REFS phase -- validateRefs's per-ref checks
// (under refs/, valid UTF-8, advertisement-safe name; well-formed 40-hex target)
// -- with a bidirectional accept/reject contract, the third sibling of
// FuzzValidatePackSet (pack phase) and FuzzValidateMeta (meta phase). The refs
// map is the root of trust for git's ref advertisement: the helper emits each
// entry as "<oid> <name>" on its own protocol line, so a Validate-accepted ref
// name carrying a newline/space would inject a forged advertisement line and a
// malformed oid would mis-frame it. No prior manifest fuzzer pins this phase
// bidirectionally: FuzzEncodeRoundTrip varies a single ref but only round-trips on
// the accept side (a false rejection or, worse, a false acceptance of an
// injection-bearing ref slips past it), and FuzzDecode rarely synthesizes valid
// multi-ref JSON. With meta valid and packs nil (both trivially valid),
// validateRefs is the ONLY phase that can reject, so Validate accepts IFF every
// ref in the map has a valid name and a valid oid; the oracle re-derives that
// independently (refNameValid restating the name contract, isHexLen(_, 40)
// restating the object-id check IsLowerHex(_, 40)) and asserts the biconditional over a
// two-ref map, which also exercises the per-ref conjunction and the
// map-iteration-order independence of the decision.
func FuzzValidateRefs(f *testing.F) {
	f.Add(uint8(2), "", uint8(0), "a", uint8(3), "dev", uint8(0), "b")          // two distinct valid refs: accept
	f.Add(uint8(2), "", uint8(0), "a", uint8(2), "", uint8(0), "b")             // same valid name collapses: accept
	f.Add(uint8(1), "notaref", uint8(0), "a", uint8(2), "", uint8(0), "b")      // name lacks refs/ prefix: reject
	f.Add(uint8(2), "", uint8(1), "nothex", uint8(3), "dev", uint8(0), "b")     // arbitrary oid on a surviving valid ref: reject
	f.Add(uint8(2), "", uint8(2), "a", uint8(3), "dev", uint8(0), "b")          // 39-hex oid (wrong length) on a surviving valid ref: reject
	f.Add(uint8(0), "heads/main\n", uint8(0), "a", uint8(2), "", uint8(0), "b") // newline in name (advert-unsafe): reject
	f.Add(uint8(0), "heads/ x", uint8(0), "a", uint8(2), "", uint8(0), "b")     // space in name (advert-unsafe): reject

	f.Fuzz(func(t *testing.T, name1Mode uint8, name1Raw string, oid1Mode uint8, oid1Raw string,
		name2Mode uint8, name2Raw string, oid2Mode uint8, oid2Raw string) {
		refs := map[string]string{}
		// Insert order is fixed (ref 1 then ref 2): if both names collapse to the
		// same key, ref 2's oid wins in the final map, and the oracle iterates that
		// same final map, so production and oracle always agree on the survivor.
		refs[refName(name1Mode, name1Raw)] = refOID(oid1Mode, oid1Raw)
		refs[refName(name2Mode, name2Raw)] = refOID(oid2Mode, oid2Raw)

		m := &Manifest{
			Version:    Version,
			RepoID:     repoID, // valid 32-hex from manifest_test.go
			Generation: 1,
			Refs:       refs,
			// Head "" and Packs nil are trivially valid, so the refs phase is the
			// only possible rejecter and the biconditional below is sound.
		}

		// Independently re-derive refs validity over the FINAL (post-collapse) map.
		// With meta valid and packs nil, these are the exact and only conditions
		// under which Validate (hence Encode) accepts.
		refsOK := true
		for name, oid := range refs {
			if !refNameValid(name) || !isHexLen(oid, 40) {
				refsOK = false
			}
		}

		enc, err := Encode(m)
		if (err != nil) == refsOK {
			if err != nil {
				t.Fatalf("Validate rejected a valid ref set %v: %v", refs, err)
			}
			t.Fatalf("Validate ACCEPTED an invalid ref set %v", refs)
		}
		if err != nil {
			return // correctly rejected
		}

		// Accepted: the canonical bytes must Decode back and re-Encode identically.
		m2, err := Decode(enc)
		if err != nil {
			t.Fatalf("Encode produced output Decode rejected: %v\n%s", err, enc)
		}
		enc2, err := Encode(m2)
		if err != nil {
			t.Fatalf("re-Encode of round-tripped manifest failed: %v", err)
		}
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("refs round trip not stable:\n first: %s\nsecond: %s", enc, enc2)
		}
	})
}

// FuzzRejectsUnknownField pins Decode's anti-smuggling guard. Decode sets
// json.DisallowUnknownFields precisely so a hostile remote "cannot smuggle data
// past clients via fields this build ignores" (manifest.go): the manifest is the
// client's root of trust, so any field outside the schema must be a hard
// rejection, never a silently-dropped extension point. The unit test pins only
// one fixed top-level field ("sneaky":true); this generalizes the guarantee over
// arbitrary field names AND the nested Pack object -- Go's DisallowUnknownFields
// recurses into nested structs, a distinct smuggling site the unit test misses.
// FuzzDecode's arbitrary bytes essentially never synthesize a valid manifest
// carrying exactly one extra well-formed unknown field, so this branch was
// effectively unexercised by the coverage-guided codec fuzzer.
func FuzzRejectsUnknownField(f *testing.F) {
	// A valid base carrying one pack, so both injection sites (top level and the
	// nested pack object) start from an otherwise-accepted manifest, making the
	// injected field the sole reason for any rejection.
	base := mustEncode(f, valid())

	f.Add("sneaky", "true", false)      // the unit test's top-level case
	f.Add("ghost", "null", true)        // unknown field inside a pack object
	f.Add("", "123", false)             // empty field name
	f.Add("x", "not valid json", false) // value coerced to a JSON string
	f.Add("Version", "1", false)        // case-variant of a known field: skipped
	f.Add("replaces", "[]", true)       // known pack field at the pack site: skipped
	f.Add("size", "5", false)           // pack-only field name at the top level: rejected

	knownTop := jsonFieldNames(reflect.TypeOf(Manifest{}))
	knownPack := jsonFieldNames(reflect.TypeOf(Pack{}))

	f.Fuzz(func(t *testing.T, field, valueRaw string, intoPack bool) {
		// Scope to ASCII names so strings.EqualFold below is exactly Go's json key
		// matching (the decoder ASCII-case-folds keys); a non-ASCII name reaches
		// the same decoder branch and adds no coverage while risking a Unicode
		// simple-fold mismatch with Go's matcher (e.g. the Kelvin sign folds to k).
		if !asciiOnly(field) {
			return
		}
		// A name that case-insensitively matches a field of the injection SITE's
		// schema is not unknown there -- Go's decoder maps it to that field -- so it
		// is out of scope for this contract and must not be asserted as a rejection.
		schema := knownTop
		if intoPack {
			schema = knownPack
		}
		for _, k := range schema {
			if strings.EqualFold(field, k) {
				return
			}
		}

		doc := injectField(t, base, field, validJSONValue(valueRaw), intoPack)
		if _, err := Decode(doc); err == nil {
			t.Fatalf("Decode accepted an unknown field %q (intoPack=%v):\n%s", field, intoPack, doc)
		}
	})
}

// mustEncode encodes m or fails the fuzz setup; used to derive a known-valid
// base document the targets mutate.
func mustEncode(f *testing.F, m *Manifest) []byte {
	b, err := Encode(m)
	if err != nil {
		f.Fatalf("base manifest does not encode: %v", err)
	}
	return b
}

// jsonFieldNames returns the JSON object key each exported field of struct type
// t decodes from -- the schema's recognized names, read straight from the json
// tags (the same ground truth Go's decoder matches against), so the oracle
// tracks the schema rather than restating a hardcoded list.
func jsonFieldNames(t reflect.Type) []string {
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "" {
			name = t.Field(i).Name
		}
		names = append(names, name)
	}
	return names
}

// asciiOnly reports whether s is pure 7-bit ASCII.
func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// validJSONValue returns raw as a JSON value when it already is one, else encodes
// it as a JSON string. The injected value must be syntactically valid JSON so the
// document parses far enough for the decoder to reach (and reject on) the unknown
// field name, rather than failing earlier on a tokenizer error.
func validJSONValue(raw string) json.RawMessage {
	if json.Valid([]byte(raw)) {
		return json.RawMessage(raw)
	}
	enc, _ := json.Marshal(raw) // any Go string marshals to a valid JSON string
	return enc
}

// injectField returns base (a valid manifest JSON document) with field->value
// added either at the top level or inside its first pack object. The caller has
// already ensured field collides with no schema name at that site, so the result
// differs from an accepted manifest by exactly one unknown field.
func injectField(t *testing.T, base []byte, field string, value json.RawMessage, intoPack bool) []byte {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(base, &top); err != nil {
		t.Fatalf("base manifest is not a JSON object: %v", err)
	}
	if intoPack {
		var packs []map[string]json.RawMessage
		if err := json.Unmarshal(top["packs"], &packs); err != nil || len(packs) == 0 {
			t.Fatalf("base manifest has no pack to inject into: %v", err)
		}
		packs[0][field] = value
		repacked, err := json.Marshal(packs)
		if err != nil {
			t.Fatalf("re-marshaling packs: %v", err)
		}
		top["packs"] = repacked
	} else {
		top[field] = value
	}
	doc, err := json.Marshal(top)
	if err != nil {
		t.Fatalf("re-marshaling manifest: %v", err)
	}
	return doc
}

// FuzzValidatePackIDs pins the pack phase's per-id WELL-FORMEDNESS sub-gate --
// the malformed-pack-id branch (validatePack) and the malformed-Replaces-id
// branch (validatePackReplaces) -- with a bidirectional accept/reject oracle. It
// is the symmetric complement of FuzzValidatePackSet: that target fuzzes the
// cross-pack STRUCTURE (duplicate ids, live-vs-replaces overlap, sizes) while
// holding every id well-formed (drawn from packPool), so it deliberately never
// reaches the well-formedness checks (its own oracle notes pool ids "are always
// well-formed ... the ONLY reasons Validate can reject"); this target fuzzes the
// id STRINGS of one pack and its Replaces while holding the structure trivially
// valid (single pack, in-range size), so id/Replaces well-formedness is the only
// thing that can vary the verdict. Those two branches gate an attacker-controlled
// manifest on the Decode read path -- a hostile remote can put any string in a
// pack id or a Replaces entry -- yet had no bidirectional oracle: FuzzValidatePackSet
// excludes them by construction, and FuzzEncodeRoundTrip executes them but returns
// early on rejection without checking the rejection was warranted, so a false
// ACCEPTANCE of a malformed id would slip past every prior manifest fuzzer.
func FuzzValidatePackIDs(f *testing.F) {
	valid := strings.Repeat("a", 64) // a well-formed pack id
	other := strings.Repeat("b", 64)
	f.Add(valid, "", false)                     // well-formed id, no replaces: accept
	f.Add("xyz", "", false)                     // too-short id: reject
	f.Add(strings.Repeat("A", 64), "", false)   // uppercase hex: reject (the pack-id check is lowercase-only)
	f.Add("", "", false)                        // empty id: reject
	f.Add(valid, other, true)                   // both well-formed, distinct: accept
	f.Add(valid, "deadbeef", true)              // malformed replaces id: reject
	f.Add(valid, valid, true)                   // replaces names the live pack: reject (overlap)
	f.Add("", other, true)                      // malformed id shields a well-formed replaces: reject
	f.Add(valid, strings.Repeat("c", 65), true) // over-length replaces id: reject

	f.Fuzz(func(t *testing.T, packID, repID string, withReplace bool) {
		p := Pack{ID: packID, Size: 1024} // size trivially in [0, maxPackSize]
		if withReplace {
			p.Replaces = []string{repID}
		}
		m := &Manifest{
			Version:    Version,
			RepoID:     repoID, // valid 32-hex from manifest_test.go
			Generation: 1,
			Refs:       map[string]string{},
			Packs:      []Pack{p},
		}

		// Independently re-derive the verdict. Meta+refs are valid, there is a
		// single pack so there is no duplicate-id collision, and the size is in
		// range, so the ONLY rejection causes are: a malformed pack id, or (when a
		// Replaces entry is present) a malformed Replaces id, or a Replaces entry
		// naming the one live pack (id-vs-replaces overlap). isHexLen(_, 64) is an
		// independent restatement of the pack-id check. A malformed pack id is checked
		// first (validatePack runs before validateReplaces), so it shields the
		// Replaces check; for accept/reject that ordering is irrelevant -- the
		// manifest is rejected iff some violation exists.
		idValid := isHexLen(packID, 64)
		wantReject := !idValid
		if idValid && withReplace {
			// The pack id is well-formed and recorded in seen; the Replaces id is
			// rejected if malformed, or flagged as overlap if it equals the live
			// pack id (repID == packID implies repID is itself hex64).
			if !isHexLen(repID, 64) || repID == packID {
				wantReject = true
			}
		}

		enc, err := Encode(m)
		if (err != nil) != wantReject {
			if err != nil {
				t.Fatalf("Validate rejected a well-formed pack set: packID=%q repID=%q withReplace=%v err=%v",
					packID, repID, withReplace, err)
			}
			t.Fatalf("Validate ACCEPTED a pack set with a malformed/overlapping id: packID=%q repID=%q withReplace=%v",
				packID, repID, withReplace)
		}
		if wantReject {
			return
		}
		// Accepted: hold it to the byte-stable Decode/Encode round trip, like the
		// sibling Validate-phase targets.
		m2, err := Decode(enc)
		if err != nil {
			t.Fatalf("Encode produced output Decode rejected: %v\n%s", err, enc)
		}
		enc2, err := Encode(m2)
		if err != nil {
			t.Fatalf("re-Encode of round-tripped manifest failed: %v", err)
		}
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("write round trip not stable:\n first: %s\nsecond: %s", enc, enc2)
		}
	})
}

// FuzzValidatePackCount pins Validate's PACK-COUNT cap -- the len(m.Packs) >
// maxPacks guard at the top of validatePacks -- the one Validate rejection cause
// none of the sibling pack-phase fuzzers reach: FuzzValidatePackSet and
// FuzzValidatePackIDs both bound their generated pack list far below maxPacks (64
// and 1 respectively), so the count guard is structurally unreachable there and
// FuzzValidatePackSet's oracle even marks countBad "unreachable here (capped)".
// The cap is load-bearing: maxPacks*maxPackSize == 2^62 stays below 2^64, so the
// cap is precisely what keeps geometry's cumulative pack-size arithmetic from
// overflowing -- a manifest from a hostile remote must not be able to drive that
// running total past 2^64 by declaring an unbounded number of packs.
//
// TestPackCountCap already pins the boundary itself (maxPacks accepts, maxPacks+1
// rejects) with all-valid packs. This target adds the property that unit test
// omits: the count check runs FIRST, before any per-pack check, so an over-count
// manifest is rejected with the count-cap error even when it ALSO carries a
// per-pack violation (a duplicate id, an over-cap size, or a malformed id). A
// regression that moved the count check below the per-pack loop would surface a
// different (per-pack) error for such a manifest; a regression that dropped the
// count check would accept an over-count all-valid manifest. The fuzz input
// straddles the cap (n in [maxPacks-1, maxPacks+2]) and selects an optional
// per-pack violation, so both sides of the boundary and the ordering interplay
// are exercised. No byte-stable round trip is asserted here -- that is
// FuzzValidatePackSet's job, and Encoding a >16K-pack manifest every execution
// would only slow the target without exercising the count cap.
func FuzzValidatePackCount(f *testing.F) {
	const (
		modeValid   = 0 // all packs well-formed and unique
		modeDup     = 1 // two packs share an id
		modeBadSize = 2 // one pack's size exceeds maxPackSize
		modeBadID   = 3 // one pack's id is malformed
	)
	f.Add(uint8(1), uint8(modeValid))   // exactly maxPacks, all valid: accept
	f.Add(uint8(2), uint8(modeValid))   // maxPacks+1, all valid: reject (count)
	f.Add(uint8(2), uint8(modeDup))     // maxPacks+1 with a duplicate: count error still wins
	f.Add(uint8(2), uint8(modeBadID))   // maxPacks+1 with a malformed id: count error still wins
	f.Add(uint8(0), uint8(modeDup))     // maxPacks-1 with a duplicate: reject (per-pack)
	f.Add(uint8(0), uint8(modeBadSize)) // maxPacks-1 with an over-cap size: reject (per-pack)
	f.Add(uint8(0), uint8(modeValid))   // maxPacks-1, all valid: accept

	f.Fuzz(func(t *testing.T, over, mode uint8) {
		// n straddles the cap: maxPacks-1 .. maxPacks+2 (so n is always >= 2 and
		// every per-pack injection site below exists).
		n := maxPacks - 1 + int(over%4)
		packs := make([]Pack, n)
		for i := range packs {
			packs[i] = Pack{ID: fmt.Sprintf("%064x", i), Size: 1}
		}
		// Inject at most one per-pack violation.
		perPackBad := false
		switch mode % 4 {
		case modeDup:
			packs[1].ID = packs[0].ID
			perPackBad = true
		case modeBadSize:
			packs[0].Size = maxPackSize + 1
			perPackBad = true
		case modeBadID:
			packs[0].ID = "not-a-hex-pack-id"
			perPackBad = true
		}

		m := &Manifest{
			Version:    Version,
			RepoID:     repoID, // valid 32-hex from manifest_test.go
			Generation: 1,
			Refs:       map[string]string{},
			Packs:      packs,
		}
		err := m.Validate()

		// The count-cap error ("%d packs exceeds maximum %d") is distinguished from
		// the size-cap error ("... size %d exceeds maximum %d") by the "packs
		// exceeds maximum" substring, which the size message never contains.
		switch {
		case n > maxPacks:
			// Over the cap: the count check fires first, so Validate rejects with
			// the count-cap error regardless of any per-pack violation present.
			if err == nil {
				t.Fatalf("Validate ACCEPTED %d packs (cap %d, mode=%d)", n, maxPacks, mode%4)
			}
			if !strings.Contains(err.Error(), "packs exceeds maximum") {
				t.Fatalf("over-count manifest (%d packs, mode=%d) rejected by a non-count check: %v",
					n, mode%4, err)
			}
		case perPackBad:
			// Within the cap but carrying a per-pack violation: must reject, and NOT
			// via the count cap.
			if err == nil {
				t.Fatalf("Validate ACCEPTED %d packs with a per-pack violation (mode=%d)", n, mode%4)
			}
			if strings.Contains(err.Error(), "packs exceeds maximum") {
				t.Fatalf("in-cap manifest (%d packs) wrongly rejected by the count cap: %v", n, err)
			}
		default:
			// Within the cap, all packs valid and unique: must accept.
			if err != nil {
				t.Fatalf("Validate rejected %d valid packs (cap %d): %v", n, maxPacks, err)
			}
		}
	})
}

// isJSONWhitespace reports whether b is one of the four bytes the JSON grammar
// (and encoding/json's scanner) treats as insignificant whitespace: space, tab,
// line feed, carriage return. Nothing else -- form feed, vertical tab, NUL, or
// any multibyte rune -- counts, so the oracle below flags every other trailing
// byte as significant data Decode must reject.
func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// FuzzDecodeTrailingData pins a second Decode guard alongside
// FuzzRejectsUnknownField: an honest manifest is EXACTLY one JSON object, and
// Decode must reject any non-whitespace bytes appended after it. json.Decoder's
// Decode reads only the first JSON value and silently leaves the rest of the
// stream unread, so before this guard a manifest blob of "{valid}{...}" or
// "{valid}garbage" decoded the first object and ignored everything after it --
// a host (or a keyed party who can mint plaintext) could smuggle a second
// manifest object or arbitrary bytes that this build silently drops while other
// tooling might read them differently, the same data-smuggling threat the
// DisallowUnknownFields guard defends against from inside the object.
//
// The oracle is a clean biconditional with no carve-out: Decode accepts the
// blob IFF every appended byte is JSON whitespace (matching json.Unmarshal,
// which tolerates trailing whitespace but rejects any trailing value), and on
// the accept side the decoded manifest must re-Encode to the exact original
// bytes -- proving the tolerated whitespace was genuinely ignored, not absorbed
// into the parse. Encode never emits trailing bytes (a single compact
// json.Marshal value), so this guard is behavior-neutral for every honest
// manifest and changes the verdict only for blobs that already carried smuggled
// trailing data. Longer fixed shapes (a second full manifest object, a partial
// object) are pinned by TestDecodeRejectsTrailingData; this target fuzzes the
// arbitrary-byte boundary.
func FuzzDecodeTrailingData(f *testing.F) {
	// A non-trivial valid manifest (refs + a nested pack) so the trailing bytes
	// follow a real multi-field object, not a degenerate "{}".
	base := mustEncode(f, valid())

	f.Add("")        // no trailing data: accept
	f.Add(" ")       // a single trailing space: accept (whitespace)
	f.Add("\n")      // trailing newline: accept
	f.Add("\t \r\n") // mixed trailing whitespace: accept
	f.Add("garbage") // trailing letters: reject
	f.Add("{}")      // a second JSON object: reject
	f.Add("0")       // a bare trailing number: reject
	f.Add("  x")     // whitespace then a non-whitespace byte: reject
	f.Add("\x00")    // a trailing NUL (not JSON whitespace): reject
	f.Add("\x0c")    // form feed -- whitespace in C but NOT in JSON: reject

	f.Fuzz(func(t *testing.T, trailing string) {
		// The boundary decision is "the first non-whitespace byte after the
		// object", so the contract is fully exercised by a short trailing run.
		// Feeding arbitrary-length trailing through Decode drives encoding/json's
		// instrumented tokenizer over every token shape, which explodes the fuzz
		// corpus and stalls the minimizer (the displayed exec count freezes);
		// capping to a few bytes keeps the json-tokenizer coverage bounded and the
		// target fast while still covering every boundary case.
		if len(trailing) > 8 {
			trailing = trailing[:8]
		}

		// allWhitespace also covers the empty string (vacuously true).
		allWhitespace := true
		for i := 0; i < len(trailing); i++ {
			if !isJSONWhitespace(trailing[i]) {
				allWhitespace = false
				break
			}
		}

		blob := append(append([]byte(nil), base...), trailing...)
		m, err := Decode(blob)

		if allWhitespace {
			// Whitespace-only (or empty) trailing must be tolerated, exactly as
			// json.Unmarshal tolerates it, and must not perturb the parse: the
			// decoded manifest re-Encodes to the original bytes byte-for-byte.
			if err != nil {
				t.Fatalf("Decode rejected a manifest with whitespace-only trailing %q: %v", trailing, err)
			}
			reenc, encErr := Encode(m)
			if encErr != nil {
				t.Fatalf("re-Encode of a manifest decoded with trailing %q failed: %v", trailing, encErr)
			}
			if !bytes.Equal(reenc, base) {
				t.Fatalf("trailing whitespace %q perturbed the parse:\n got %s\nwant %s", trailing, reenc, base)
			}
			return
		}

		// Any non-whitespace trailing byte is significant data Decode must reject:
		// accepting it would let a second object or arbitrary bytes ride along
		// unnoticed past the manifest this build actually reads.
		if err == nil {
			t.Fatalf("Decode ACCEPTED a manifest with non-whitespace trailing data %q", trailing)
		}
	})
}
