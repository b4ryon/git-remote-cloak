// Unit tests for manifest codec edges: Encode refusing invalid manifests
// and Decode normalizing a missing refs map.
package manifest

import "testing"

func TestEncodeRejectsInvalid(t *testing.T) {
	m := New()
	m.Version = 99
	if _, err := Encode(m); err == nil {
		t.Fatal("Encode accepted an unsupported version")
	}
}

func TestDecodeNormalizesNilRefs(t *testing.T) {
	m, err := Decode([]byte(`{"version":1,"repo_id":"0123456789abcdef0123456789abcdef","generation":1,"packs":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Refs == nil {
		t.Fatal("Decode left Refs nil")
	}
}

func TestDecodeRejectsUnknownField(t *testing.T) {
	_, err := Decode([]byte(`{"version":1,"repo_id":"0123456789abcdef0123456789abcdef","generation":1,"packs":[],"sneaky":true}`))
	if err == nil {
		t.Fatal("Decode accepted an unknown field")
	}
}
