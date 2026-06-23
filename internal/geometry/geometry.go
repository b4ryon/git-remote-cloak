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

	split := -1
	var cum uint64
	for i, p := range sorted {
		if i > 0 && smaller(p.Size, factor, cum) {
			split = i
		}
		cum += uint64(p.Size)
	}
	if split < 1 {
		return nil
	}
	var combined uint64
	for i := 0; i <= split; i++ {
		combined += uint64(sorted[i].Size)
	}
	for j := split + 1; j < len(sorted); j++ {
		if smaller(sorted[j].Size, factor, combined) {
			combined += uint64(sorted[j].Size)
			split = j
		} else {
			break
		}
	}
	return sorted[:split+1]
}

// Holds reports whether the invariant holds for the given sizes.
func Holds(packs []manifest.Pack, factor int) bool {
	return Victims(packs, factor) == nil
}
