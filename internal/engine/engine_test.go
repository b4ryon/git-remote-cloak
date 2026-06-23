// Unit tests for engine logic that needs no git host: the HEAD symref
// heuristic used by list.
package engine

import (
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

const oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func m(head string, refs ...string) *manifest.Manifest {
	mm := manifest.New()
	mm.Head = head
	for _, r := range refs {
		mm.Refs[r] = oid
	}
	return mm
}

func TestHeadForList(t *testing.T) {
	cases := []struct {
		name string
		m    *manifest.Manifest
		want string
	}{
		{"nil manifest", nil, ""},
		{"manifest head wins", m("refs/heads/dev", "refs/heads/dev", "refs/heads/main"), "refs/heads/dev"},
		{"dangling head ignored", m("refs/heads/gone", "refs/heads/main"), "refs/heads/main"},
		{"main preferred", m("", "refs/heads/zz", "refs/heads/main", "refs/heads/master"), "refs/heads/main"},
		{"master second", m("", "refs/heads/zz", "refs/heads/master"), "refs/heads/master"},
		{"first alphabetical", m("", "refs/heads/zeta", "refs/heads/alpha"), "refs/heads/alpha"},
		{"tags only", m("", "refs/tags/v1"), ""},
	}
	for _, c := range cases {
		if got := HeadForList(c.m); got != c.want {
			t.Errorf("%s: HeadForList = %q, want %q", c.name, got, c.want)
		}
	}
}
