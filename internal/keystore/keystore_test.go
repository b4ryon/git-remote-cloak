// Unit tests for the keystore: generation, export/import, file backend
// permission handling, and the redaction guarantees of the Key type.
package keystore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateUnique(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Export() == b.Export() {
		t.Fatal("two generated keys are identical")
	}
}

func TestExportRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseExport(k.Export() + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.Export() != k.Export() || got.ID() != k.ID() {
		t.Fatal("export round trip mismatch")
	}
	if _, err := ParseExport("not-a-key"); err == nil {
		t.Fatal("ParseExport accepted garbage")
	}
}

func TestFileSaveLoad(t *testing.T) {
	ref := "file:" + filepath.Join(t.TempDir(), "sub", "key")
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(ref, k); err != nil {
		t.Fatal(err)
	}
	got, err := Load(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.Export() != k.Export() {
		t.Fatal("file round trip mismatch")
	}
	fi, err := os.Stat(strings.TrimPrefix(ref, "file:"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %04o, want 0600", perm)
	}
}

func TestFileSaveRefusesOverwrite(t *testing.T) {
	ref := "file:" + filepath.Join(t.TempDir(), "key")
	k, _ := Generate()
	if err := Save(ref, k); err != nil {
		t.Fatal(err)
	}
	if err := Save(ref, k); err == nil {
		t.Fatal("Save overwrote an existing key file")
	}
}

func TestLoadRejectsOpenPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	k, _ := Generate()
	if err := os.WriteFile(path, []byte(k.Export()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("file:" + path); err == nil {
		t.Fatal("Load accepted a group/world-readable key file")
	}
}

func TestKeyRedactionEverywhere(t *testing.T) {
	raw := make([]byte, KeySize)
	for i := range raw {
		raw[i] = 0xAB
	}
	k, err := NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	leaks := []string{
		hex.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		string(raw),
	}
	jsonOut, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	jsonStruct, err := json.Marshal(struct{ K Key }{k})
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{
		"%v":          fmt.Sprintf("%v", k),
		"%+v":         fmt.Sprintf("%+v", k),
		"%#v":         fmt.Sprintf("%#v", k),
		"%s":          fmt.Sprintf("%s", k),
		"%x":          fmt.Sprintf("%x", k),
		"%q":          fmt.Sprintf("%q", k),
		"json":        string(jsonOut),
		"json-struct": string(jsonStruct),
		"slog-value":  fmt.Sprintf("%v", k.LogValue()),
	}
	for name, out := range outputs {
		for _, leak := range leaks {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked key material: %q", name, out)
			}
		}
		if !strings.Contains(out, "redacted") {
			t.Fatalf("%s does not look redacted: %q", name, out)
		}
	}
}
