// Fuzz tests for the cli package's host/source-data parsers and manifest
// consumers. parseSeedRefs is the seed-path manifest-construction parser: it
// turns `git for-each-ref --format=%(objectname) %(refname)` output from the
// source repository into the generation-1 manifest's ref name->oid map (and
// the ordered want oids fed to pack-objects), so it is squarely in the
// manifest-parsing objective area - the inverse direction of the manifest READ
// path, building the Refs map that Encode/Decode later round-trips.
// FuzzParseSeedRefs pins its faithfulness and line-skip robustness against an
// independent SplitN decomposition.
//
// FuzzStatusPackStats covers the read-side: packSizeStats and countAppliedLive
// are the cli `status` command's pure consumers of a Decode/Validate-accepted
// manifest's pack list, pinning their size-arithmetic and applied-intersection
// contract (including the proof that the total never overflows int64, which
// rests on the manifest's maxPacks*maxPackSize == 2^62 size cap).
//
// FuzzSeedManifest covers the write-side genesis builder: seedManifest (lifted
// out of buildSeedManifest) is the fourth distinct manifest pack-set
// construction contract after the engine's repackManifest (replace-all),
// nextPushManifest (append-retaining-all), and consolidatedPacks (drop-victims).
// It pins the genesis-specific invariants (generation exactly 1, a single pack,
// empty Replaces) that Validate cannot see, plus byte-stable persistence.
package cli

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

// FuzzParseSeedRefs fuzzes parseSeedRefs over arbitrary `for-each-ref` output,
// pinning its full contract against an independent oracle: the result must
// equal a SplitN-based re-derivation (a genuinely different decomposition of
// the same trim+first-space-split semantics), every retained ref value must
// appear in the ordered wants list, dedup can only shrink the map relative to
// wants, and the parse is deterministic.
func FuzzParseSeedRefs(f *testing.F) {
	// Genuine for-each-ref shapes plus the line-skip edges the parser must
	// tolerate (blank lines, spaceless noise, surrounding whitespace, empty
	// oid, duplicate names, embedded-space and tab-separated names).
	f.Add("")
	f.Add("5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e refs/heads/main")
	f.Add("0000000000000000000000000000000000000001 refs/heads/main\n" +
		"0000000000000000000000000000000000000002 refs/heads/dev\n" +
		"0000000000000000000000000000000000000003 refs/tags/v1\n")
	f.Add("\n\nabc refs/heads/main\n\n")
	f.Add("garbage-with-no-space\n")
	f.Add("   abc refs/heads/x   \n")
	f.Add("aaa refs/heads/dup\nbbb refs/heads/dup\n") // duplicate name: last wins
	f.Add(" refs/heads/x\n  \n")                      // empty-oid / all-whitespace lines skipped
	f.Add("abc refs/heads/with space and more\n")     // name keeps everything after first space
	f.Add("abc\trefs/heads/tabbed\n")                 // tab is not an ASCII space: line skipped

	f.Fuzz(func(t *testing.T, out string) {
		refs, wants := parseSeedRefs(out)

		if refs == nil {
			t.Fatal("parseSeedRefs returned a nil refs map; it must always be non-nil")
		}

		// Independent oracle: re-derive refs/wants via SplitN(line, " ", 2)
		// rather than strings.Cut. len(parts)==2 iff a space is present (==
		// Cut's found), and parts[0]==the pre-space oid, so this is provably
		// the same semantics expressed as a different decomposition.
		expRefs := map[string]string{}
		var expWants []string
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
			if len(parts) != 2 || parts[0] == "" {
				continue
			}
			expRefs[parts[1]] = parts[0]
			expWants = append(expWants, parts[0])
		}
		if !maps.Equal(refs, expRefs) {
			t.Fatalf("refs mismatch: got %v want %v (input %q)", refs, expRefs, out)
		}
		if !slices.Equal(wants, expWants) {
			t.Fatalf("wants mismatch: got %v want %v (input %q)", wants, expWants, out)
		}

		// Structural invariants the build relies on: dedup can only shrink the
		// map relative to the per-line wants, and every retained ref oid was
		// genuinely appended to wants (so pack-objects packs every ref tip).
		if len(refs) > len(wants) {
			t.Fatalf("len(refs)=%d exceeds len(wants)=%d (input %q)", len(refs), len(wants), out)
		}
		for name, oid := range refs {
			if !slices.Contains(wants, oid) {
				t.Fatalf("ref %q -> %q not present in wants %v (input %q)", name, oid, wants, out)
			}
		}

		// Determinism: a second parse of the same bytes yields equal results.
		refs2, wants2 := parseSeedRefs(out)
		if !maps.Equal(refs, refs2) || !slices.Equal(wants, wants2) {
			t.Fatalf("non-deterministic parse for input %q", out)
		}
	})
}

// FuzzStatusPackStats fuzzes the cli `status` command's pure manifest-pack
// consumers, packSizeStats and countAppliedLive, over arbitrary pack-size
// sequences. Both run only on Validate-accepted manifests in production, so the
// fuzz constructs packs that already satisfy the post-Validate pack invariant
// (0 <= Size <= maxPackSize, count <= maxPacks) and pins:
//   - packSizeStats: total == sum, largest == max, smallest == min for a
//     non-empty list and smallest == -1 (the "smallest %d" status-line
//     sentinel) for an empty one, checked against an independent uint64 oracle
//     that also proves total never overflows int64 (the manifest's
//     maxPacks*maxPackSize == 2^62 cap keeps the sum below 2^63);
//   - countAppliedLive: counts exactly the live packs whose id is in the
//     applied set, never an applied id that names no live pack.
func FuzzStatusPackStats(f *testing.F) {
	// Production manifest caps (mirrors the unexported manifest.maxPackSize /
	// manifest.maxPacks): a Validate-accepted manifest guarantees every pack
	// size is in [0, maxPackSize] and there are at most maxPacks packs.
	const (
		maxPackSize = int64(1) << 48
		maxPacks    = 1 << 14
	)

	// build encodes a pack-size sequence as 8-byte big-endian groups, the form
	// the fuzz body decodes back into per-pack sizes.
	build := func(sizes ...uint64) []byte {
		b := make([]byte, len(sizes)*8)
		for i, s := range sizes {
			binary.BigEndian.PutUint64(b[i*8:], s)
		}
		return b
	}

	f.Add([]byte(nil), uint64(0))                      // empty: smallest sentinel -1
	f.Add(build(0), uint64(1))                         // single zero-size pack, applied
	f.Add(build(1, 2, 3), uint64(0b101))               // ascending sizes, packs 0 and 2 applied
	f.Add(build(7, 7, 7), ^uint64(0))                  // equal sizes, all applied
	f.Add(build(uint64(maxPackSize), 0), uint64(0b10)) // max + zero, only the second applied
	// Boundary: maxPacks packs each at maxPackSize drives total to exactly
	// 2^62, the worst case the no-overflow proof must hold for.
	bigSizes := make([]uint64, maxPacks)
	for i := range bigSizes {
		bigSizes[i] = uint64(maxPackSize)
	}
	f.Add(build(bigSizes...), ^uint64(0))

	f.Fuzz(func(t *testing.T, data []byte, appliedMask uint64) {
		n := len(data) / 8
		if n > maxPacks {
			n = maxPacks
		}
		packs, applied, o := buildFuzzPacks(data, n, appliedMask, maxPackSize, maxPacks)

		total, largest, smallest := packSizeStats(packs)
		assertPackSizeStats(t, total, largest, smallest, o, n, maxPackSize)

		got := assertCountAppliedLive(t, packs, applied, o.applied, n, appliedMask)

		assertStatsDeterministic(t, packs, applied, total, largest, smallest, got)
	})
}

// packStatsOracle is the independently-accumulated expectation for a fuzzed
// pack-size sequence: the uint64 sum (which also witnesses the no-overflow
// proof), the max/min sizes, and the count of applied live packs.
type packStatsOracle struct {
	usum     uint64
	largest  int64
	smallest int64
	applied  int
}

// buildFuzzPacks decodes data into n production-shaped packs (each size clamped
// into the post-Validate range [0, maxPackSize]), records which are applied per
// appliedMask, and accumulates the independent oracle alongside construction. It
// also seeds two ghost applied ids that name no live pack, which countAppliedLive
// must never count.
func buildFuzzPacks(data []byte, n int, appliedMask uint64, maxPackSize int64, maxPacks int) ([]manifest.Pack, map[string]bool, packStatsOracle) {
	packs := make([]manifest.Pack, n)
	applied := map[string]bool{}
	o := packStatsOracle{smallest: -1}

	for i := 0; i < n; i++ {
		// Clamp each decoded value into the post-Validate size range
		// [0, maxPackSize] so the fuzzed packs are production-shaped; the
		// modulo's range is exactly [0, maxPackSize] so the boundary is
		// reachable.
		v := binary.BigEndian.Uint64(data[i*8:])
		size := int64(v % uint64(maxPackSize+1))
		id := fmt.Sprintf("%064x", i) // distinct, valid 64-hex pack id

		packs[i] = manifest.Pack{ID: id, Size: size}
		o.usum += uint64(size)
		if size > o.largest {
			o.largest = size
		}
		if o.smallest < 0 || size < o.smallest {
			o.smallest = size
		}
		if appliedMask&(uint64(1)<<(uint(i)%64)) != 0 {
			applied[id] = true
			o.applied++
		}
	}
	// Ghost applied ids that name no live pack must never be counted.
	applied["ghost-not-a-live-pack"] = true
	applied[fmt.Sprintf("%064x", maxPacks+1)] = true
	return packs, applied, o
}

// assertPackSizeStats pins packSizeStats against the oracle: the int64 total
// equals the uint64 sum exactly (so it never wrapped negative under the
// maxPacks*maxPackSize == 2^62 cap), largest/smallest match the max/min, and the
// empty-list sentinel (0,0,-1) vs the non-empty ordering contract both hold.
func assertPackSizeStats(t *testing.T, total, largest, smallest int64, o packStatsOracle, n int, maxPackSize int64) {
	t.Helper()
	// No-overflow proof: the sum fits in uint64 (<= 2^62 by the cap) and
	// equals the int64 total exactly, so total never wrapped negative.
	if o.usum > math.MaxInt64 {
		t.Fatalf("oracle sum %d exceeds MaxInt64 (n=%d); cap invariant broken", o.usum, n)
	}
	if total != int64(o.usum) {
		t.Fatalf("total=%d want %d (n=%d)", total, o.usum, n)
	}
	if total < 0 {
		t.Fatalf("total=%d went negative (overflow) for n=%d", total, n)
	}
	if largest != o.largest {
		t.Fatalf("largest=%d want %d (n=%d)", largest, o.largest, n)
	}
	if smallest != o.smallest {
		t.Fatalf("smallest=%d want %d (n=%d)", smallest, o.smallest, n)
	}

	// Empty-list sentinel vs the non-empty ordering contract.
	if n == 0 {
		if total != 0 || largest != 0 || smallest != -1 {
			t.Fatalf("empty stats = (%d,%d,%d) want (0,0,-1)", total, largest, smallest)
		}
	} else if smallest < 0 || smallest > largest || largest > maxPackSize {
		t.Fatalf("bad ordering: smallest=%d largest=%d maxPackSize=%d", smallest, largest, maxPackSize)
	}
}

// assertCountAppliedLive pins countAppliedLive: it counts exactly the live packs
// whose id is in the applied set, never an applied id that names no live pack,
// and never more than the live pack count. It returns the count for the
// determinism check.
func assertCountAppliedLive(t *testing.T, packs []manifest.Pack, applied map[string]bool, expApplied, n int, appliedMask uint64) int {
	t.Helper()
	got := countAppliedLive(packs, applied)
	if got != expApplied {
		t.Fatalf("countAppliedLive=%d want %d (n=%d, mask=%#x)", got, expApplied, n, appliedMask)
	}
	if got > n {
		t.Fatalf("countAppliedLive=%d exceeds live pack count %d", got, n)
	}
	return got
}

// assertStatsDeterministic re-evaluates both consumers on the same inputs and
// pins that they reproduce their first results exactly.
func assertStatsDeterministic(t *testing.T, packs []manifest.Pack, applied map[string]bool, total, largest, smallest int64, got int) {
	t.Helper()
	total2, largest2, smallest2 := packSizeStats(packs)
	if total2 != total || largest2 != largest || smallest2 != smallest {
		t.Fatal("packSizeStats non-deterministic")
	}
	if countAppliedLive(packs, applied) != got {
		t.Fatal("countAppliedLive non-deterministic")
	}
}

// FuzzSeedManifest pins seedManifest, the genesis (generation-1) manifest
// builder lifted out of buildSeedManifest. This manifest is the root of trust
// for a freshly seeded remote: it becomes the first rollback pin (generation 1)
// and carries the repo-identity anchor, so a construction bug here corrupts the
// entire trust chain from its origin.
//
// buildSeedManifest does Encode (hence Validate) its result, but Validate cannot
// see the genesis-specific invariants -- it accepts ANY generation, ANY pack
// count, and a non-empty Replaces -- so a builder that emitted the wrong
// generation, an extra/missing pack, or a spurious Replaces would still produce
// a structurally VALID manifest and slip past every manifest Validate fuzzer.
// Those self-enforced invariants are exactly what this target pins (the iter-58
// nextPushManifest rationale applied to the seed path).
func FuzzSeedManifest(f *testing.F) {
	const (
		repo32 = "0123456789abcdef0123456789abcdef"
		id64   = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	)
	// Seeds: a typical single-branch seed, an empty-refs/empty-head edge, a
	// multi-ref seed, arbitrary-bytes repo id/pack id (construction must not
	// care about field validity), and a negative size.
	f.Add(repo32, "refs/heads/main", []byte{1}, id64, int64(4096))
	f.Add(repo32, "", []byte{}, id64, int64(0))
	f.Add(repo32, "refs/heads/dev", []byte{1, 2, 3}, id64, int64(1<<40))
	f.Add("not-a-repo-id", "whatever", []byte{0}, "not-a-pack-id", int64(-1))
	f.Add("", "", []byte{5, 5}, "", int64(7))

	f.Fuzz(func(t *testing.T, repoID, head string, refsSeed []byte, packID string, packSize int64) {
		// Build the published ref set from the seed bytes (each distinct byte
		// adds one entry; duplicates collapse last-wins, exactly as a source
		// repo's for-each-ref output would). The construction contract is a
		// wholesale install, so the map's content/validity is irrelevant here.
		refs := map[string]string{}
		for _, b := range refsSeed {
			refs[fmt.Sprintf("refs/heads/r%d", b)] = fmt.Sprintf("%040x", b)
		}
		// Independent snapshot of the input refs (NOT via manifest.Clone) to
		// observe the wholesale install without depending on Clone correctness.
		wantRefs := maps.Clone(refs)

		m := seedManifest(repoID, head, refs, packID, packSize)

		assertSeedFields(t, m, repoID, head, wantRefs)
		assertSeedPack(t, m, packID, packSize)
		assertSeedPersistence(t, m)
		assertSeedDeterministic(t, repoID, head, wantRefs, packID, packSize, m)
	})
}

// assertSeedFields pins the genesis header invariants Validate cannot see: the
// wire version from manifest.New, generation exactly 1 (the rollback baseline,
// not a bump of a prior generation), the repo-identity/head anchors installed
// verbatim, and the refs installed wholesale.
func assertSeedFields(t *testing.T, m *manifest.Manifest, repoID, head string, wantRefs map[string]string) {
	t.Helper()
	// Version carried from manifest.New (the build's wire version).
	if m.Version != manifest.Version {
		t.Fatalf("Version = %d, want %d", m.Version, manifest.Version)
	}
	// Generation is exactly 1: the genesis is NOT a bump of some prior
	// generation, it is the rollback baseline the first pin records.
	if m.Generation != 1 {
		t.Fatalf("Generation = %d, want 1 (genesis baseline)", m.Generation)
	}
	// Repo identity and head installed verbatim (the repo id is the
	// substitution-detection anchor; both must survive unchanged).
	if m.RepoID != repoID {
		t.Fatalf("RepoID = %q, want %q", m.RepoID, repoID)
	}
	if m.Head != head {
		t.Fatalf("Head = %q, want %q", m.Head, head)
	}
	// Refs installed wholesale.
	if !maps.Equal(m.Refs, wantRefs) {
		t.Fatalf("Refs = %v, want %v", m.Refs, wantRefs)
	}
}

// assertSeedPack pins the single-pack genesis invariant: exactly one pack
// carrying the given id/size and NO Replaces. A seed has no prior packs to
// supersede, so a non-empty Replaces would falsely claim to retire packs that
// never existed (the packSkippable contract), and any count other than one would
// mis-describe the single packed history.
func assertSeedPack(t *testing.T, m *manifest.Manifest, packID string, packSize int64) {
	t.Helper()
	if len(m.Packs) != 1 {
		t.Fatalf("got %d packs, want exactly 1 (genesis)", len(m.Packs))
	}
	p := m.Packs[0]
	if p.ID != packID || p.Size != packSize || len(p.Replaces) != 0 {
		t.Fatalf("seed pack = {%q,%d,replaces=%v}, want {%q,%d,nil}",
			p.ID, p.Size, p.Replaces, packID, packSize)
	}
}

// assertSeedPersistence pins the persistence tie: buildSeedManifest's next step
// is manifest.Encode (which validates). Encoding is not guaranteed to succeed
// for arbitrary (invalid) fuzzed fields, but WHEN it does the manifest must
// round-trip byte-stably through Decode -- the seed-path analog of the accepted-
// manifest round trips the manifest Validate fuzzers pin.
func assertSeedPersistence(t *testing.T, m *manifest.Manifest) {
	t.Helper()
	enc, err := manifest.Encode(m)
	if err != nil {
		return
	}
	dec, err := manifest.Decode(enc)
	if err != nil {
		t.Fatalf("Decode of an Encode-accepted seed manifest failed: %v", err)
	}
	enc2, err := manifest.Encode(dec)
	if err != nil {
		t.Fatalf("re-Encode of decoded seed manifest failed: %v", err)
	}
	if !bytes.Equal(enc, enc2) {
		t.Fatalf("seed manifest not byte-stable across Decode/Encode")
	}
}

// assertSeedDeterministic pins that a rebuild from a fresh refs clone reproduces
// the same manifest header and single pack.
func assertSeedDeterministic(t *testing.T, repoID, head string, wantRefs map[string]string, packID string, packSize int64, m *manifest.Manifest) {
	t.Helper()
	m2 := seedManifest(repoID, head, maps.Clone(wantRefs), packID, packSize)
	if m2.Version != m.Version || m2.Generation != m.Generation ||
		m2.RepoID != m.RepoID || m2.Head != m.Head ||
		!maps.Equal(m2.Refs, wantRefs) || len(m2.Packs) != 1 ||
		m2.Packs[0].ID != packID || m2.Packs[0].Size != packSize {
		t.Fatal("seedManifest not deterministic")
	}
}
