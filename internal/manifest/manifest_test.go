// Unit tests for the manifest codec: round trips and validation rejections.
package manifest

import (
	"fmt"
	"strings"
	"testing"
)

const (
	oidA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	packA  = "1111111111111111111111111111111111111111111111111111111111111111"
	packB  = "2222222222222222222222222222222222222222222222222222222222222222"
	repoID = "0123456789abcdef0123456789abcdef"
)

func valid() *Manifest {
	return &Manifest{
		Version:    Version,
		RepoID:     repoID,
		Generation: 41,
		Head:       "refs/heads/main",
		Refs:       map[string]string{"refs/heads/main": oidA},
		Packs:      []Pack{{ID: packA, Size: 1234, Replaces: []string{packB}}},
	}
}

func TestRoundTrip(t *testing.T) {
	b, err := Encode(valid())
	if err != nil {
		t.Fatal(err)
	}
	m, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Generation != 41 || m.Head != "refs/heads/main" ||
		m.Refs["refs/heads/main"] != oidA || len(m.Packs) != 1 || m.Packs[0].ID != packA {
		t.Fatalf("round trip mismatch: %+v", m)
	}
}

func TestValidationRejections(t *testing.T) {
	cases := map[string]func(*Manifest){
		"bad version":        func(m *Manifest) { m.Version = 0 },
		"missing repo id":    func(m *Manifest) { m.RepoID = "" },
		"malformed repo id":  func(m *Manifest) { m.RepoID = "xyz" },
		"non-branch head":    func(m *Manifest) { m.Head = "refs/tags/v1" },
		"bad ref name":       func(m *Manifest) { m.Refs["main"] = oidA },
		"bad oid":            func(m *Manifest) { m.Refs["refs/heads/x"] = "zzz" },
		"bad pack id":        func(m *Manifest) { m.Packs[0].ID = "short" },
		"negative size":      func(m *Manifest) { m.Packs[0].Size = -1 },
		"oversize pack":      func(m *Manifest) { m.Packs[0].Size = maxPackSize + 1 },
		"bad replaces id":    func(m *Manifest) { m.Packs[0].Replaces = []string{"nope"} },
		"replaces live pack": func(m *Manifest) { m.Packs[0].Replaces = []string{packA} },
		"duplicate pack ids": func(m *Manifest) { m.Packs = append(m.Packs, m.Packs[0]) },
	}
	for name, mutate := range cases {
		m := valid()
		mutate(m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: Validate accepted invalid manifest", name)
		}
	}
}

func TestPackCountCap(t *testing.T) {
	m := valid()
	m.Packs = make([]Pack, 0, maxPacks+1)
	for i := 0; i <= maxPacks; i++ { // maxPacks+1 unique, well-formed packs
		m.Packs = append(m.Packs, Pack{ID: fmt.Sprintf("%064x", i), Size: 1})
	}
	if err := m.Validate(); err == nil {
		t.Fatalf("Validate accepted %d packs (cap %d)", len(m.Packs), maxPacks)
	}
	// Exactly at the cap must still pass.
	m.Packs = m.Packs[:maxPacks]
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate rejected %d packs at cap %d: %v", len(m.Packs), maxPacks, err)
	}
}

func TestDecodeGarbage(t *testing.T) {
	if _, err := Decode([]byte("not json")); err == nil {
		t.Fatal("Decode accepted garbage")
	}
	if _, err := Decode([]byte(`{"version":7}`)); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("Decode accepted unsupported version: %v", err)
	}
}

func TestCloneIsDeep(t *testing.T) {
	m := valid()
	c := m.Clone()
	c.Refs["refs/heads/main"] = strings.Repeat("b", 40)
	c.Packs[0].Replaces[0] = packA
	if m.Refs["refs/heads/main"] != oidA || m.Packs[0].Replaces[0] != packB {
		t.Fatal("Clone shares state with original")
	}
}
