// Unit and property tests for geometric consolidation planning: known
// cases, and a simulation proving repeated merge restores the invariant
// and terminates for arbitrary size sequences.
package geometry

import (
	"fmt"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

func packs(sizes ...int64) []manifest.Pack {
	out := make([]manifest.Pack, len(sizes))
	for i, s := range sizes {
		out[i] = manifest.Pack{ID: fmt.Sprintf("%064d", i), Size: s}
	}
	return out
}

func sizesOf(ps []manifest.Pack) []int64 {
	out := make([]int64, len(ps))
	for i, p := range ps {
		out[i] = p.Size
	}
	return out
}

func TestVictimsCases(t *testing.T) {
	cases := []struct {
		name   string
		sizes  []int64
		factor int
		want   int // number of victims; 0 = invariant holds
	}{
		{"single pack", []int64{100}, 2, 0},
		{"holds big-small", []int64{1000, 100}, 2, 0},
		{"two equal smalls", []int64{100, 100}, 2, 2},
		{"big plus two smalls", []int64{10000, 100, 100}, 2, 2},
		{"cascade into mid", []int64{1000, 300, 300}, 2, 3},
		{"factor zero disables", []int64{100, 100}, 0, 0},
		{"all equal", []int64{50, 50, 50, 50}, 2, 4},
	}
	for _, c := range cases {
		got := Victims(packs(c.sizes...), c.factor)
		if len(got) != c.want {
			t.Errorf("%s: victims = %d (%v), want %d", c.name, len(got), sizesOf(got), c.want)
		}
	}
}

func TestMergeSimulationRestoresInvariant(t *testing.T) {
	// Pseudo-random but deterministic sequences (no real randomness in
	// tests): repeated push-then-consolidate must always terminate with
	// the invariant holding, regardless of arrival order.
	seq := []int64{7, 13, 5, 900, 11, 11, 11, 4000, 3, 3, 64, 64, 64, 1, 2, 5000, 9, 9}
	var live []manifest.Pack
	for i, s := range seq {
		live = append(live, manifest.Pack{ID: fmt.Sprintf("%032d%032d", i, i), Size: s})
		for round := 0; ; round++ {
			if round > len(seq) {
				t.Fatalf("consolidation did not terminate at step %d (sizes %v)", i, sizesOf(live))
			}
			victims := Victims(live, 2)
			if victims == nil {
				break
			}
			if len(victims) < 2 {
				t.Fatalf("planner returned %d victims", len(victims))
			}
			inVictims := map[string]bool{}
			var merged int64
			for _, v := range victims {
				inVictims[v.ID] = true
				merged += v.Size
			}
			var next []manifest.Pack
			for _, p := range live {
				if !inVictims[p.ID] {
					next = append(next, p)
				}
			}
			live = append(next, manifest.Pack{ID: fmt.Sprintf("%016d%048d", i, merged), Size: merged})
		}
		if !Holds(live, 2) {
			t.Fatalf("invariant broken after step %d: %v", i, sizesOf(live))
		}
	}
	if len(live) > 6 {
		t.Fatalf("consolidation ineffective: %d live packs for %d pushes (%v)", len(live), len(seq), sizesOf(live))
	}
}
