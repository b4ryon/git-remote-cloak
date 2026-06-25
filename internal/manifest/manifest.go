// Package manifest defines cloak's encrypted manifest: the root of trust on
// the remote. It maps refs to object ids, lists the live encrypted packs
// (whose ids are SHA-256 of ciphertext, doubling as integrity pointers),
// carries the monotonic generation counter used for rollback detection, and
// records which branch HEAD pointed at so clones check out the right branch.
// The plaintext is versioned JSON; it is stored only inside AEAD ciphertext.
package manifest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Version is the manifest schema version this build reads and writes. v1
// added the bound repo identity (RepoID); v0 manifests (no repo id) are
// rejected by Validate as an unsupported version.
const Version = 1

// maxPackSize caps a single pack's recorded ciphertext size; maxPacks caps how
// many packs a manifest may list. The per-pack cap alone does not bound the
// SUM of pack sizes, so geometry's running totals (package geometry) need the
// count cap too: maxPacks*maxPackSize == 2^62 stays below 2^64, so the uint64
// accumulation cannot overflow even over an (AEAD-valid but) adversarial
// manifest. Both are far above cloak's few-hundred-MB, logarithmically-packed
// working scale, so honest manifests never approach either.
const (
	maxPackSize = 1 << 48
	maxPacks    = 1 << 14
)

var (
	packIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	oidRe    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// hasAdvertUnsafeByte reports whether s contains an ASCII control character
// (including newline and carriage return) or a space. The helper builds git's
// line-oriented ref advertisement by formatting "<oid> <name>" and "@<head>
// HEAD" one per line (internal/helper list), so a ref name or head carrying a
// newline would inject a forged advertisement line into git's protocol stream,
// and a space would be misparsed as the start of a ref attribute. All such bytes
// are also forbidden in git ref names, so an honest manifest never contains one;
// the manifest is the advertisement's root of trust, so it must reject them.
// Every flagged byte is < 0x21 or == 0x7f (pure ASCII), and this runs only after
// utf8.ValidString, so a valid multi-byte UTF-8 rune (continuation bytes >= 0x80)
// is never falsely flagged.
func hasAdvertUnsafeByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// Pack describes one live encrypted packfile on the remote.
type Pack struct {
	// ID is the lowercase hex SHA-256 of the ciphertext blob.
	ID string `json:"id"`
	// Size is the ciphertext size in bytes (drives geometric consolidation).
	Size int64 `json:"size"`
	// Replaces lists pack ids this pack superseded at consolidation, so a
	// client that already applied them can skip downloading this one.
	Replaces []string `json:"replaces,omitempty"`
}

// Manifest is the decrypted manifest content.
type Manifest struct {
	Version int `json:"version"`
	// RepoID is a random per-repository identity minted at first push and
	// carried forward unchanged through consolidation and rekey. Bound inside
	// the AEAD manifest and pinned locally (TOFU), it lets a client reject a
	// host that substitutes another repository's genuine state under the same
	// shared key.
	RepoID     string            `json:"repo_id"`
	Generation uint64            `json:"generation"`
	Head       string            `json:"head,omitempty"`
	Refs       map[string]string `json:"refs"`
	Packs      []Pack            `json:"packs"`
}

// New returns an empty manifest at generation 0. The caller must set a
// RepoID (see NewRepoID) before the manifest will validate; only the two
// from-scratch creation sites mint one, every other path carries the
// existing id forward via Clone.
func New() *Manifest {
	return &Manifest{Version: Version, Refs: map[string]string{}}
}

// NewRepoID mints a fresh random repository identity (16 bytes of
// crypto/rand as 32 hex chars).
func NewRepoID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Encode validates and serializes the manifest.
func Encode(m *Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// Decode deserializes and validates a manifest. Unknown fields are rejected
// so a host cannot smuggle data past clients via fields this build ignores.
func Decode(b []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	// An honest manifest is exactly one JSON object: Encode emits a single
	// compact json.Marshal value with no trailing bytes. json.Decoder.Decode
	// reads only the first value and would silently ignore anything after it,
	// so a second object or arbitrary bytes appended past the manifest would
	// pass unnoticed. Require the stream to end (modulo JSON whitespace, which
	// json.Unmarshal also tolerates) so trailing data cannot be smuggled past
	// clients, mirroring the DisallowUnknownFields anti-smuggling guard above.
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("manifest: unexpected trailing data after manifest object")
	}
	if m.Refs == nil {
		m.Refs = map[string]string{}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks structural invariants. It runs the four validation phases
// in order (meta, refs, packs, replaces), threading the live-pack set built by
// validatePacks into the Replaces cross-check.
func (m *Manifest) Validate() error {
	if err := m.validateMeta(); err != nil {
		return err
	}
	if err := m.validateRefs(); err != nil {
		return err
	}
	seen, err := m.validatePacks()
	if err != nil {
		return err
	}
	return m.validateReplaces(seen)
}

// validateMeta checks the version, repo id, and head invariants.
func (m *Manifest) validateMeta() error {
	if m.Version != Version {
		return fmt.Errorf("manifest: unsupported version %d (this build speaks %d)", m.Version, Version)
	}
	if !repoIDRe.MatchString(m.RepoID) {
		return fmt.Errorf("manifest: missing or malformed repo id %q", m.RepoID)
	}
	if m.Head != "" && !strings.HasPrefix(m.Head, "refs/heads/") {
		return fmt.Errorf("manifest: head %q is not a branch ref", m.Head)
	}
	// The manifest is JSON, which cannot represent non-UTF-8 strings: encoding a
	// branch name with invalid UTF-8 would silently coerce it to U+FFFD and
	// corrupt the stored head. Fail closed instead so the write is faithful.
	if !utf8.ValidString(m.Head) {
		return fmt.Errorf("manifest: head %q is not valid UTF-8", m.Head)
	}
	// The head is emitted as "@<head> HEAD" in the ref advertisement, so a
	// control character or space in it would corrupt git's protocol stream.
	if hasAdvertUnsafeByte(m.Head) {
		return fmt.Errorf("manifest: head %q contains a control character or space", m.Head)
	}
	return nil
}

// validateRefs checks that every ref name is under refs/ and every target is a
// well-formed object id.
func (m *Manifest) validateRefs() error {
	for name, oid := range m.Refs {
		if !strings.HasPrefix(name, "refs/") {
			return fmt.Errorf("manifest: ref name %q does not start with refs/", name)
		}
		// JSON cannot faithfully represent a non-UTF-8 ref name: marshaling
		// would replace the invalid bytes with U+FFFD and silently corrupt the
		// stored ref. Reject it so the manifest stays a faithful copy.
		if !utf8.ValidString(name) {
			return fmt.Errorf("manifest: ref name %q is not valid UTF-8", name)
		}
		// A ref name becomes "<oid> <name>" on its own advertisement line, so a
		// control character (notably a newline) or space would inject or corrupt
		// a line in git's protocol stream. Reject it at the root of trust.
		if hasAdvertUnsafeByte(name) {
			return fmt.Errorf("manifest: ref name %q contains a control character or space", name)
		}
		if !oidRe.MatchString(oid) {
			return fmt.Errorf("manifest: ref %q has malformed object id %q", name, oid)
		}
	}
	return nil
}

// validatePacks checks the pack count cap and each pack's id (well-formed and
// unique) and size, returning the set of live pack ids for the Replaces check.
func (m *Manifest) validatePacks() (map[string]bool, error) {
	if len(m.Packs) > maxPacks {
		return nil, fmt.Errorf("manifest: %d packs exceeds maximum %d", len(m.Packs), maxPacks)
	}
	seen := make(map[string]bool, len(m.Packs))
	for _, p := range m.Packs {
		if err := validatePack(p, seen); err != nil {
			return nil, err
		}
	}
	return seen, nil
}

// validatePack checks one pack's id (well-formed and not already in seen) and
// size, recording its id in seen. The checks run in id, duplicate, then size
// order so a pack failing several rules reports the same error as the inline
// loop did.
func validatePack(p Pack, seen map[string]bool) error {
	if !packIDRe.MatchString(p.ID) {
		return fmt.Errorf("manifest: malformed pack id %q", p.ID)
	}
	if seen[p.ID] {
		return fmt.Errorf("manifest: duplicate pack id %q", p.ID)
	}
	seen[p.ID] = true
	if p.Size < 0 {
		return fmt.Errorf("manifest: pack %q has negative size %d", p.ID, p.Size)
	}
	if p.Size > maxPackSize {
		return fmt.Errorf("manifest: pack %q size %d exceeds maximum %d", p.ID, p.Size, maxPackSize)
	}
	return nil
}

// validateReplaces checks that every Replaces id is well-formed and does not
// name a still-live pack: a pack cannot both be live and superseded.
func (m *Manifest) validateReplaces(seen map[string]bool) error {
	for _, p := range m.Packs {
		if err := validatePackReplaces(p, seen); err != nil {
			return err
		}
	}
	return nil
}

// validatePackReplaces checks one pack's Replaces ids: each must be well-formed
// and must not name a still-live pack (present in seen).
func validatePackReplaces(p Pack, seen map[string]bool) error {
	for _, r := range p.Replaces {
		if !packIDRe.MatchString(r) {
			return fmt.Errorf("manifest: pack %q replaces malformed id %q", p.ID, r)
		}
		if seen[r] {
			return fmt.Errorf("manifest: pack %q replaces live pack id %q", p.ID, r)
		}
	}
	return nil
}

// PackIDs returns the set of live pack ids.
func (m *Manifest) PackIDs() map[string]bool {
	out := make(map[string]bool, len(m.Packs))
	for _, p := range m.Packs {
		out[p.ID] = true
	}
	return out
}

// Clone returns a deep copy. A nil Packs is preserved as nil (rather than
// normalized to an empty slice) so a clone re-encodes byte-for-byte identically
// to its source ("packs":null vs "packs":[]) and reflect.DeepEqual(m, m.Clone())
// holds; this mirrors how each pack's Replaces slice is already nil-preserving.
func (m *Manifest) Clone() *Manifest {
	c := &Manifest{Version: m.Version, RepoID: m.RepoID, Generation: m.Generation, Head: m.Head,
		Refs: make(map[string]string, len(m.Refs))}
	for k, v := range m.Refs {
		c.Refs[k] = v
	}
	if m.Packs != nil {
		c.Packs = make([]Pack, 0, len(m.Packs))
		for _, p := range m.Packs {
			cp := Pack{ID: p.ID, Size: p.Size, Replaces: append([]string(nil), p.Replaces...)}
			c.Packs = append(c.Packs, cp)
		}
	}
	return c
}
