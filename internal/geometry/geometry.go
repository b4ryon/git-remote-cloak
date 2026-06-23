// Package geometry implements the pure math of cloak's geometric pack
// consolidation (modeled on git's geometric repacking): on ciphertext
// sizes sorted ascending, every pack must be at least factor times the sum
// of all smaller packs. When the invariant breaks, the smallest violating
// prefix (extended while the merged result still violates against the next
// pack) is consolidated into one pack. Amortized upload cost stays
// logarithmic; no fixed-cadence full-history re-upload exists.
package geometry

import (
	"math/bits"
	"sort"

	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

// smaller reports whether size < factor*cum, computed without overflow: a
// product that exceeds 64 bits is by definition larger than any non-negative
// pack size. Pack sizes are non-negative (manifest.Validate) and capped, so
// uint64 math is exact here.
func smaller(size int64, factor int, cum uint64) bool {
	hi, lo := bits.Mul64(uint64(factor), cum)
	if hi != 0 {
		return true
	}
	return uint64(size) < lo
}

// Victims returns the packs that must merge to restore the invariant, or
// nil when it already holds. A non-nil result always has at least 2 packs.
func Victims(packs []manifest.Pack, factor int) []manifest.Pack {
	if factor <= 0 || len(packs) < 2 {
		return nil
	}
	sorted := append([]manifest.Pack(nil), packs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Size < sorted[j].Size })

	split := initialSplit(sorted, factor)
	if split < 1 {
		return nil
	}
	split = extendSplit(sorted, factor, split)
	return sorted[:split+1]
}

// initialSplit returns the highest index i (>=1) at which the invariant
// breaks, i.e. pack i is smaller than factor times the running sum of all
// strictly-smaller packs, scanning sorted-ascending. It returns -1 when no
// such violation exists (the invariant already holds).
func initialSplit(sorted []manifest.Pack, factor int) int {
	split := -1
	var cum uint64
	for i, p := range sorted {
		if i > 0 && smaller(p.Size, factor, cum) {
			split = i
		}
		cum += uint64(p.Size)
	}
	return split
}

// extendSplit grows the victim prefix beyond split while each next pack still
// violates against the running merged sum, returning the final split index.
func extendSplit(sorted []manifest.Pack, factor, split int) int {
	var combined uint64
	for i := 0; i <= split; i++ {
		combined += uint64(sorted[i].Size)
	}
	for j := split + 1; j < len(sorted); j++ {
		if !smaller(sorted[j].Size, factor, combined) {
			break
		}
		combined += uint64(sorted[j].Size)
		split = j
	}
	return split
}

// Holds reports whether the invariant holds for the given sizes.
func Holds(packs []manifest.Pack, factor int) bool {
	return Victims(packs, factor) == nil
}
