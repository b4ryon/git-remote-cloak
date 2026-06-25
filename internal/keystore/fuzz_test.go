// Fuzz tests for the keystore master-key transfer codec and key-reference
// scheme classifier. Export/ParseExport is the one place untrusted bytes (a key
// file written on disk or a keychain blob) are parsed back into a master Key, so
// FuzzParseExport* pin its round-trip faithfulness and fail-closed prefix/length
// gate. FuzzClassifyRef pins classifyRef -- the operator/config-influenced
// scheme parser Load/Save/Delete share to route a reference to a backend -- and
// its fail-closed contract that only an exact "file"/"keychain" scheme is ever
// routed to a key store.
package keystore

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

// fuzzKeyBytes normalizes arbitrary fuzz input to exactly KeySize bytes so it is
// always a valid NewKey input: short seeds zero-pad, long seeds truncate.
func fuzzKeyBytes(seed []byte) []byte {
	b := make([]byte, KeySize)
	copy(b, seed)
	return b
}

// FuzzParseExportRoundTrip pins the transfer codec's faithfulness contract:
// ParseExport(k.Export()) recovers a byte-identical key for any key material,
// and the parse tolerates the surrounding whitespace the real read path carries
// (saveFile appends "\n", ParseExport TrimSpace-es before decoding).
func FuzzParseExportRoundTrip(f *testing.F) {
	f.Add([]byte{}, "", "")
	f.Add(make([]byte, KeySize), "\n", "")
	f.Add([]byte("0123456789abcdef0123456789abcdef"), "  \t", "\n ")
	f.Fuzz(func(t *testing.T, seed []byte, lead, trail string) {
		// Only whitespace may surround the export; any other byte changes the
		// input that ParseExport sees after TrimSpace and breaks the round trip.
		if strings.TrimSpace(lead) != "" || strings.TrimSpace(trail) != "" {
			t.Skip()
		}
		material := fuzzKeyBytes(seed)
		k, err := NewKey(material)
		if err != nil {
			t.Fatalf("NewKey(%d bytes) failed: %v", len(material), err)
		}
		got, err := ParseExport(lead + k.Export() + trail)
		if err != nil {
			t.Fatalf("ParseExport of a genuine export failed: %v", err)
		}
		if !bytes.Equal(got.Bytes(), material) {
			t.Fatalf("round-trip key bytes mismatch")
		}
		if got.ID() != k.ID() {
			t.Fatalf("round-trip ID mismatch: %q vs %q", got.ID(), k.ID())
		}
		if got.Export() != k.Export() {
			t.Fatalf("round-trip Export mismatch")
		}
	})
}

// FuzzParseExportArbitrary asserts ParseExport never panics on host- or
// attacker-controlled bytes (a tampered key file or keychain blob) and fails
// closed: it accepts an input only when, after trimming, it carries the cloak
// export prefix AND the base64 body decodes to exactly KeySize bytes. Any
// accepted key is non-zero, KeySize, deterministic, and re-exports identically.
func FuzzParseExportArbitrary(f *testing.F) {
	f.Add("not-a-key")
	f.Add(exportPrefix)
	f.Add(exportPrefix + "@@@@") // invalid base64 body
	f.Add(exportPrefix + base64.StdEncoding.EncodeToString([]byte("short")))
	f.Add("  " + exportPrefix + base64.StdEncoding.EncodeToString(make([]byte, KeySize)) + "  ")
	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParseExport(s)
		if err != nil {
			// A rejected input must fail closed: no key material returned.
			if !k.IsZero() {
				t.Fatalf("ParseExport returned an error but a non-zero key")
			}
			return
		}
		// Accepted: the prefix gate must have passed on the trimmed input, so a
		// blob that is not tagged as a cloak key is never accepted as one.
		trimmed := strings.TrimSpace(s)
		if !strings.HasPrefix(trimmed, exportPrefix) {
			t.Fatalf("ParseExport accepted input without the %q prefix: %q", exportPrefix, s)
		}
		// Accepted: it must be a full master key, never a short/long one.
		if k.IsZero() || len(k.Bytes()) != KeySize {
			t.Fatalf("ParseExport accepted a non-KeySize key: zero=%v len=%d", k.IsZero(), len(k.Bytes()))
		}
		// Determinism: parsing the same bytes twice yields the same key.
		k2, err := ParseExport(s)
		if err != nil || !bytes.Equal(k.Bytes(), k2.Bytes()) {
			t.Fatalf("ParseExport is not deterministic")
		}
		// Self-consistency: an accepted key's own Export re-parses identically.
		again, err := ParseExport(k.Export())
		if err != nil || !bytes.Equal(again.Bytes(), k.Bytes()) {
			t.Fatalf("accepted key's Export does not re-parse identically")
		}
	})
}

// assertRefRejected checks that a malformed or unknown-scheme reference is
// rejected by all three public operations with a KeyUnavailable error and no
// side effect (each returns from its malformed/unknown arm before touching any
// backend, so Save can be handed a zero Key it never reads).
func assertRefRejected(t *testing.T, ref string) {
	t.Helper()
	failsClosed := func(op string, err error) {
		if err == nil {
			t.Fatalf("%s(%q) accepted a malformed/unknown reference", op, ref)
		}
		if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.KeyUnavailable {
			t.Fatalf("%s(%q) error kind = %v (ok=%v), want KeyUnavailable", op, ref, kind, ok)
		}
	}
	k, err := Load(ref)
	failsClosed("Load", err)
	if !k.IsZero() {
		t.Fatalf("Load(%q) returned a non-zero key alongside a rejection", ref)
	}
	failsClosed("Save", Save(ref, Key{}))
	failsClosed("Delete", Delete(ref))
}

// FuzzClassifyRef pins the key-reference scheme classifier that Load, Save, and
// Delete share to route a reference to the file/keychain backend or reject it.
// The reference is operator/config-influenced (it comes from cloak.keyRef), so
// the load-bearing contract is fail-closed: only an exact "file"/"keychain"
// scheme before the first ":" selects a backend, and everything else (no colon,
// or any other scheme) is rejected -- never silently routed to a key store.
func FuzzClassifyRef(f *testing.F) {
	f.Add("file:/home/user/.config/cloak/keys/default")
	f.Add("keychain:cloak-master-key")
	f.Add("nocolon")
	f.Add("bogus:whatever")
	f.Add("")
	f.Add(":")
	f.Add("file:")
	f.Add("file:a:b:c") // rest keeps every byte after the FIRST colon
	f.Add("File:/x")    // case-sensitive: "File" is not "file"
	f.Add(" file:/x")   // a leading space is part of the scheme, so unrecognized
	f.Add("keychain")   // a recognized word without a colon is still malformed
	f.Fuzz(func(t *testing.T, ref string) {
		kind, scheme, rest := classifyRef(ref)

		// Independent decomposition: split on the FIRST ':' via IndexByte, a
		// different mechanism than the implementation's strings.Cut. ':' is a
		// single ASCII byte, so both split at the identical offset.
		idx := strings.IndexByte(ref, ':')
		var wantKind refKind
		var wantScheme, wantRest string
		if idx < 0 {
			wantKind, wantScheme, wantRest = refMalformed, ref, ""
		} else {
			wantScheme, wantRest = ref[:idx], ref[idx+1:]
			switch wantScheme {
			case "file":
				wantKind = refFile
			case "keychain":
				wantKind = refKeychain
			default:
				wantKind = refUnknown
			}
		}
		if kind != wantKind || scheme != wantScheme || rest != wantRest {
			t.Fatalf("classifyRef(%q) = (%d,%q,%q), want (%d,%q,%q)",
				ref, kind, scheme, rest, wantKind, wantScheme, wantRest)
		}

		// Fail-closed: the result is always one of the four known kinds, and a
		// backend is selected ONLY for an exact recognized scheme.
		switch kind {
		case refMalformed, refFile, refKeychain, refUnknown:
		default:
			t.Fatalf("classifyRef(%q) returned out-of-range kind %d", ref, kind)
		}
		if (kind == refFile) != (idx >= 0 && ref[:idx] == "file") {
			t.Fatalf("refFile classification disagrees with an exact \"file\" scheme for %q", ref)
		}
		if (kind == refKeychain) != (idx >= 0 && ref[:idx] == "keychain") {
			t.Fatalf("refKeychain classification disagrees with an exact \"keychain\" scheme for %q", ref)
		}

		// Faithful reconstruction: a backend reference loses no byte of its
		// path/name; the classified pieces rebuild the original exactly.
		if idx < 0 {
			if scheme != ref || rest != "" {
				t.Fatalf("malformed ref %q did not reconstruct: scheme=%q rest=%q", ref, scheme, rest)
			}
		} else if scheme+":"+rest != ref {
			t.Fatalf("ref %q did not reconstruct from scheme=%q rest=%q", ref, scheme, rest)
		}

		// Determinism.
		if k2, s2, r2 := classifyRef(ref); k2 != kind || s2 != scheme || r2 != rest {
			t.Fatalf("classifyRef(%q) is not deterministic", ref)
		}

		// End-to-end fail-closed tie: a malformed or unknown reference must be
		// rejected by every public operation, confirming the classification
		// surfaces as the observable refusal to route to any backend.
		if kind == refMalformed || kind == refUnknown {
			assertRefRejected(t, ref)
		}
	})
}
