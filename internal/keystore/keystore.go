// Package keystore manages the cloak master key behind a small interface:
// key generation, a redacting Key type that cannot leak through logging or
// serialization, an export/import encoding for the one-time machine transfer
// and backups, and storage backends. M1 ships the file backend (0600,
// FileVault as at-rest protection); the darwin native Keychain backend with
// Touch ID gating lands in M5.
package keystore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

// ErrKeyExists is wrapped by Save when a key already exists at the reference,
// so callers (e.g. keygen) can detect it and guide the user to delete first.
var ErrKeyExists = errors.New("a key already exists at this reference")

// KeySize is the master key length in bytes (256-bit).
const KeySize = 32

// exportPrefix tags the copy-paste-safe export encoding so imports can
// validate they were handed a cloak key and not something else.
const exportPrefix = "cloak-key-v0:"

// Key holds master key bytes. It redacts itself in every formatter and
// serializer; the raw bytes are reachable only via Bytes(), which only the
// agecrypt package may consume. Key bytes MUST never reach a logger.
type Key struct {
	bytes []byte
	id    string
}

// NewKey copies b into a Key. b must be exactly KeySize bytes.
func NewKey(b []byte) (Key, error) {
	if len(b) != KeySize {
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "new key",
			"key must be %d bytes, got %d", KeySize, len(b))
	}
	cp := make([]byte, KeySize)
	copy(cp, b)
	sum := sha256.Sum256(cp)
	return Key{bytes: cp, id: hex.EncodeToString(sum[:4])}, nil
}

// Generate returns a fresh random master key.
func Generate() (Key, error) {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "generate key", err)
	}
	return NewKey(b)
}

// ID returns a short non-secret fingerprint (first 8 hex of SHA-256).
func (k Key) ID() string { return k.id }

// IsZero reports whether k holds no key material.
func (k Key) IsZero() bool { return len(k.bytes) == 0 }

// Bytes returns the raw key. RESTRICTED: only the agecrypt wrap/unwrap path
// may call this; the result must never be logged or serialized.
func (k Key) Bytes() []byte { return k.bytes }

// Wipe best-effort zeroes the key's backing bytes. This is defense in depth,
// NOT a guarantee: Go's garbage collector may relocate or have already copied
// the array, and derived material inside crypto primitives is not reached.
// All copies of a Key share one backing array, so wiping any copy clears it
// for the rest. Call when the key is no longer needed (e.g. session close).
func (k Key) Wipe() {
	for i := range k.bytes {
		k.bytes[i] = 0
	}
}

func (k Key) redacted() string {
	if k.IsZero() {
		return "[redacted:keyid=none]"
	}
	return "[redacted:keyid=" + k.id + "]"
}

// String implements fmt.Stringer with redaction.
func (k Key) String() string { return k.redacted() }

// GoString implements fmt.GoStringer with redaction (covers %#v).
func (k Key) GoString() string { return k.redacted() }

// Format implements fmt.Formatter so every verb, including %x and %+v,
// emits the redacted form instead of key bytes.
func (k Key) Format(f fmt.State, verb rune) { fmt.Fprint(f, k.redacted()) }

// MarshalJSON redacts the key in JSON output (e.g. structured logs).
func (k Key) MarshalJSON() ([]byte, error) { return json.Marshal(k.redacted()) }

// MarshalText redacts the key in text serializers.
func (k Key) MarshalText() ([]byte, error) { return []byte(k.redacted()), nil }

// LogValue redacts the key under log/slog.
func (k Key) LogValue() any { return k.redacted() }

// Export returns the copy-paste-safe transfer/backup encoding. Handle the
// result like the key itself.
func (k Key) Export() string {
	return exportPrefix + base64.StdEncoding.EncodeToString(k.bytes)
}

// ParseExport decodes the Export encoding back into a Key.
func ParseExport(s string) (Key, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, exportPrefix)
	if !ok {
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "import key",
			"input does not look like a cloak key export (missing %q prefix)", exportPrefix)
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "import key", err)
	}
	return NewKey(b)
}

// Keychain hooks, installed by keychain_darwin.go on cgo darwin builds.
var (
	keychainAvailable bool
	keychainLoad      func(name string) ([]byte, error)
	keychainSave      func(name string, data []byte) error
	keychainDelete    func(name string) error
)

// FileDefaultRef is the file-backend default location, used as the default
// keyRef on platforms without Keychain support and as the documented
// fallback on darwin.
func FileDefaultRef() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "file:cloak-master-key"
	}
	return "file:" + filepath.Join(home, ".config", "cloak", "keys", "default")
}

// Load resolves a key reference ("file:<path>" or "keychain:<name>") and
// loads the key.
func Load(ref string) (Key, error) {
	scheme, rest, found := strings.Cut(ref, ":")
	if !found {
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key",
			"malformed key reference %q (want file:<path> or keychain:<name>)", ref)
	}
	switch scheme {
	case "file":
		return loadFile(expandHome(rest))
	case "keychain":
		if !keychainAvailable {
			return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key",
				"this build has no Keychain support (non-darwin or cgo disabled); use file:<path>")
		}
		b, err := keychainLoad(rest)
		if err != nil {
			return Key{}, err
		}
		return ParseExport(string(b))
	default:
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key",
			"unknown key reference scheme %q", scheme)
	}
}

// Save stores the key at the given reference. Both backends refuse to
// overwrite an existing key.
func Save(ref string, k Key) error {
	scheme, rest, found := strings.Cut(ref, ":")
	if !found {
		return cloakerr.Newf(cloakerr.KeyUnavailable, "save key",
			"malformed key reference %q", ref)
	}
	switch scheme {
	case "file":
		return saveFile(expandHome(rest), k)
	case "keychain":
		if !keychainAvailable {
			return cloakerr.Newf(cloakerr.KeyUnavailable, "save key",
				"this build has no Keychain support (non-darwin or cgo disabled); use file:<path>")
		}
		return keychainSave(rest, []byte(k.Export()))
	default:
		return cloakerr.Newf(cloakerr.KeyUnavailable, "save key",
			"unknown key reference scheme %q", scheme)
	}
}

// Delete removes a stored key (used by tests and key rotation cleanup).
func Delete(ref string) error {
	scheme, rest, found := strings.Cut(ref, ":")
	if !found {
		return cloakerr.Newf(cloakerr.KeyUnavailable, "delete key", "malformed key reference %q", ref)
	}
	switch scheme {
	case "file":
		return os.Remove(expandHome(rest))
	case "keychain":
		if !keychainAvailable {
			return cloakerr.Newf(cloakerr.KeyUnavailable, "delete key", "no Keychain support in this build")
		}
		return keychainDelete(rest)
	default:
		return cloakerr.Newf(cloakerr.KeyUnavailable, "delete key", "unknown key reference scheme %q", scheme)
	}
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p[1:], "/"))
		}
	}
	return p
}

func loadFile(path string) (Key, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "load key file", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key file",
			"%s has mode %04o; refusing group/world-accessible key files (want 0600)", path, perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "load key file", err)
	}
	return ParseExport(string(b))
}

func saveFile(path string, k Key) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return cloakerr.New(cloakerr.KeyUnavailable, "save key file",
				fmt.Errorf("%s already exists; refusing to overwrite a key: %w", path, ErrKeyExists))
		}
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", err)
	}
	// The key file is the single most critical artifact: it decrypts every
	// repo and has no other copy. fsync it to disk before reporting success,
	// and surface the close error rather than dropping it. On the write/sync
	// failure paths the best-effort Close is cleanup only -- its error is
	// subordinate to the failure already being returned.
	if _, err := f.WriteString(k.Export() + "\n"); err != nil {
		f.Close()
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", err)
	}
	if err := f.Close(); err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", err)
	}
	return nil
}
