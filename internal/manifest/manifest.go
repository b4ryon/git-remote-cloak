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
	"regexp"
	"strings"
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
	if m.Refs == nil {
		m.Refs = map[string]string{}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks structural invariants.
func (m *Manifest) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("manifest: unsupported version %d (this build speaks %d)", m.Version, Version)
	}
	if !repoIDRe.MatchString(m.RepoID) {
		return fmt.Errorf("manifest: missing or malformed repo id %q", m.RepoID)
	}
	if m.Head != "" && !strings.HasPrefix(m.Head, "refs/heads/") {
		return fmt.Errorf("manifest: head %q is not a branch ref", m.Head)
	}
	for name, oid := range m.Refs {
		if !strings.HasPrefix(name, "refs/") {
			return fmt.Errorf("manifest: ref name %q does not start with refs/", name)
		}
		if !oidRe.MatchString(oid) {
			return fmt.Errorf("manifest: ref %q has malformed object id %q", name, oid)
		}
	}
	if len(m.Packs) > maxPacks {
		return fmt.Errorf("manifest: %d packs exceeds maximum %d", len(m.Packs), maxPacks)
	}
	seen := make(map[string]bool, len(m.Packs))
	for _, p := range m.Packs {
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
	}
	// Replaces ids must be well-formed and must not name a still-live pack: a
	// pack cannot both be live and superseded.
	for _, p := range m.Packs {
		for _, r := range p.Replaces {
			if !packIDRe.MatchString(r) {
				return fmt.Errorf("manifest: pack %q replaces malformed id %q", p.ID, r)
			}
			if seen[r] {
				return fmt.Errorf("manifest: pack %q replaces live pack id %q", p.ID, r)
			}
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

// Clone returns a deep copy.
func (m *Manifest) Clone() *Manifest {
	c := &Manifest{Version: m.Version, RepoID: m.RepoID, Generation: m.Generation, Head: m.Head,
		Refs: make(map[string]string, len(m.Refs)), Packs: make([]Pack, 0, len(m.Packs))}
	for k, v := range m.Refs {
		c.Refs[k] = v
	}
	for _, p := range m.Packs {
		cp := Pack{ID: p.ID, Size: p.Size, Replaces: append([]string(nil), p.Replaces...)}
		c.Packs = append(c.Packs, cp)
	}
	return c
}
