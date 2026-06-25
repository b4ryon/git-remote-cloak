// Fuzz test for geometric consolidation planning. Victims/Holds run on the
// pack-size list of a manifest, which originates on the (untrusted) remote, so
// the planner must never panic and must obey its structural contract for any
// size sequence a manifest could carry. The arithmetic is overflow-hardened
// (smaller uses bits.Mul64 because factor*cum can exceed 64 bits); the
// manifest's maxPackSize/maxPacks caps (internal/manifest) exist precisely to
// bound the running totals this code accumulates, so the fuzzer feeds sizes
// spanning the full [0, maxPackSize] range -- including the large-factor inputs
// that drive smaller()'s wide-multiply (bits.Mul64 hi != 0) path. The deepest
// invariant pinned here is convergence: from any pack set, repeated
// consolidate-then-merge must terminate and restore the geometric invariant,
// generalizing the single fixed sequence in geometry_test.go to all inputs.
//
// FuzzSmaller fuzzes the overflow-hardened core comparison (smaller) directly,
// against an arbitrary-precision math/big oracle. FuzzVictims reaches smaller
// only indirectly, where cum is the running sum of real pack sizes (bounded
// well under 2^62 by maxPackSize*maxPacks), so its bits.Mul64 hi != 0 overflow
// branch is barely reachable; fuzzing smaller directly sweeps cum and factor
// across the full range, deep into the > 64-bit product region the wide
// multiply exists to handle.
package geometry

import (
	"fmt"
	"math/big"
	"sort"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

// maxSize mirrors the manifest's unexported maxPackSize cap (1<<48): no pack a
// validated manifest carries exceeds it, so the fuzzer never does either. Even
// maxFuzzPacks packs at this size sum to well under int64's range, so the merge
// simulation's int64 size accumulation cannot overflow.
const maxSize = 1 << 48

// maxFuzzPacks bounds how many packs one execution builds, keeping the O(rounds)
// merge simulation fast while still covering multi-round convergence. A large
// factor (not pack count) reaches smaller()'s overflowing wide-multiply path, so
// this bound costs no coverage there.
const maxFuzzPacks = 128

// fuzzPacks turns fuzz bytes into a bounded list of non-negative pack sizes,
// reading 8 bytes per size big-endian (matching seedSizes) and masking into
// [0, maxSize]. Each pack gets a unique all-digit 64-char id.
func fuzzPacks(data []byte) []manifest.Pack {
	var ps []manifest.Pack
	for i := 0; i+8 <= len(data) && len(ps) < maxFuzzPacks; i += 8 {
		var v uint64
		for j := 0; j < 8; j++ {
			v = v<<8 | uint64(data[i+j])
		}
		ps = append(ps, manifest.Pack{ID: fmt.Sprintf("%064d", len(ps)), Size: int64(v % (maxSize + 1))})
	}
	return ps
}

// seedSizes encodes explicit sizes the way fuzzPacks decodes them (8 bytes per
// size, big-endian), so seed corpus entries map to the intended pack sizes.
func seedSizes(sizes ...int64) []byte {
	b := make([]byte, 0, 8*len(sizes))
	for _, s := range sizes {
		v := uint64(s)
		for j := 7; j >= 0; j-- {
			b = append(b, byte(v>>(8*j)))
		}
	}
	return b
}

// merge consolidates victims into one pack of their combined size, the way the
// engine's consolidation rewrites a manifest's pack set. live's lengths are
// strictly decreasing across the convergence loop (each round drops >= 2 packs
// and adds 1), so the "m"-prefixed merged id is unique within a run and never
// collides with the all-digit original ids.
func merge(live, victims []manifest.Pack) []manifest.Pack {
	inV := make(map[string]bool, len(victims))
	var sum int64
	for _, v := range victims {
		inV[v.ID] = true
		sum += v.Size
	}
	out := make([]manifest.Pack, 0, len(live)-len(victims)+1)
	for _, p := range live {
		if !inV[p.ID] {
			out = append(out, p)
		}
	}
	return append(out, manifest.Pack{ID: fmt.Sprintf("m%063d", len(live)), Size: sum})
}

// checkVictims asserts the structural contract of a single planning call: the
// result is nil (invariant holds) or names at least two victims; it agrees with
// Holds; and any non-nil result is exactly the smallest len(v) packs (Victims
// sorts ascending and returns a prefix) and required factor>0 with >=2 packs.
func checkVictims(t *testing.T, packs []manifest.Pack, factor int, v []manifest.Pack) {
	t.Helper()
	if v != nil && len(v) < 2 {
		t.Fatalf("Victims returned %d victim(s); contract is nil or >= 2 (factor %d)", len(v), factor)
	}
	if holds := Holds(packs, factor); holds != (v == nil) {
		t.Fatalf("Holds=%v disagrees with (Victims==nil)=%v (factor %d)", holds, v == nil, factor)
	}
	if v == nil {
		return
	}
	if factor <= 0 || len(packs) < 2 {
		t.Fatalf("Victims returned a non-nil result for factor %d with %d packs", factor, len(packs))
	}
	want := sizesOf(packs)
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	got := sizesOf(v)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	for i, s := range got {
		if s != want[i] {
			t.Fatalf("victim sizes %v are not the smallest %d of %v (factor %d)", got, len(v), want, factor)
		}
	}
}

func FuzzVictims(f *testing.F) {
	// Seeds mirroring the unit cases plus a large-size/large-factor edge that
	// drives smaller()'s wide-multiply (bits.Mul64 hi != 0) overflow path.
	f.Add(seedSizes(100, 100), 2)
	f.Add(seedSizes(10000, 100, 100), 2)
	f.Add(seedSizes(1000, 300, 300), 2)
	f.Add(seedSizes(50, 50, 50, 50), 2)
	f.Add(seedSizes(maxSize, maxSize), 1<<20) // factor*cum overflows 64 bits
	f.Add(seedSizes(0, 0, 0), 2)              // all-zero sizes
	f.Add([]byte{}, 0)

	f.Fuzz(func(t *testing.T, data []byte, factor int) {
		packs := fuzzPacks(data)

		// The direct contract of one planning call.
		checkVictims(t, packs, factor, Victims(packs, factor))

		// Convergence: repeated consolidate-then-merge must terminate and restore
		// the invariant for ANY size sequence. Each round removes >= 1 pack, so it
		// must finish in fewer than len(packs) rounds; exceeding that is a
		// non-termination bug.
		live := append([]manifest.Pack(nil), packs...)
		for round := 0; ; round++ {
			if round > len(packs) {
				t.Fatalf("consolidation did not terminate within %d rounds (factor %d, sizes %v)",
					len(packs), factor, sizesOf(live))
			}
			vics := Victims(live, factor)
			checkVictims(t, live, factor, vics)
			if vics == nil {
				break
			}
			live = merge(live, vics)
		}
		// Consolidation only ever shrinks the live set; it must never grow it.
		if len(live) > len(packs) {
			t.Fatalf("consolidation grew the pack set from %d to %d (factor %d)", len(packs), len(live), factor)
		}
	})
}

// bigProduct returns the exact, un-truncated product factor*cum as a big.Int,
// faithfully modeling smaller's uint64(factor)/uint64(size) casts. It is an
// arbitrary-precision decomposition entirely independent of smaller's
// bits.Mul64 hi/lo wide multiply, so comparing the two catches an error in the
// overflow-detection arithmetic rather than restating it.
func bigProduct(factor int, cum uint64) *big.Int {
	return new(big.Int).Mul(new(big.Int).SetUint64(uint64(factor)), new(big.Int).SetUint64(cum))
}

func FuzzSmaller(f *testing.F) {
	// Seeds spanning the in-range comparison, the equal/just-under boundary at
	// the manifest pack-size cap, and the wide-multiply overflow (hi != 0) path.
	f.Add(int64(50), 2, uint64(100))              // 50 < 200 -> true
	f.Add(int64(300), 2, uint64(100))             // 300 < 200 -> false
	f.Add(int64(0), 0, uint64(0))                 // 0 < 0 -> false
	f.Add(int64(maxSize), 1, uint64(maxSize))     // equal -> false (boundary)
	f.Add(int64(maxSize-1), 1, uint64(maxSize))   // just under -> true
	f.Add(int64(7), 2, uint64(1)<<63)             // factor*cum == 2^64, hi != 0 -> true
	f.Add(int64(maxSize), 1<<20, uint64(maxSize)) // product 2^68, overflow -> true
	f.Add(int64(-1), 1, uint64(1))                // robustness: uint64(size) wraps huge

	f.Fuzz(func(t *testing.T, size int64, factor int, cum uint64) {
		got := smaller(size, factor, cum)

		// Exact oracle: smaller reports uint64(size) < uint64(factor)*cum with the
		// product computed without truncation. The big.Int product models the
		// function's casts faithfully and is exact for every input, so the
		// biconditional needs no domain carve-out. For the production domain (size
		// and factor non-negative -- Validate caps sizes >= 0 and Victims rejects
		// factor <= 0) the casts are the identity, so this is exactly the
		// documented mathematical comparison size < factor*cum.
		prod := bigProduct(factor, cum)
		want := new(big.Int).SetUint64(uint64(size)).Cmp(prod) < 0
		if got != want {
			t.Fatalf("smaller(%d, %d, %d) = %v; want %v (exact product %s)", size, factor, cum, got, want, prod)
		}

		// The overflow-safety contract that justifies bits.Mul64: when the exact
		// product needs more than 64 bits it exceeds any uint64 size, so smaller
		// must report true. Pinned with a formulation distinct from the
		// implementation (BitLen vs hi != 0); a mutant that dropped the hi check
		// and compared against the truncated low word would violate it.
		if prod.BitLen() > 64 && !got {
			t.Fatalf("smaller(%d, %d, %d) = false but exact product %s exceeds 64 bits", size, factor, cum, prod)
		}

		// smaller is a pure function of its arguments.
		if again := smaller(size, factor, cum); again != got {
			t.Fatalf("smaller(%d, %d, %d) nondeterministic: %v then %v", size, factor, cum, got, again)
		}
	})
}
