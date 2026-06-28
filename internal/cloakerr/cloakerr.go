// Package cloakerr defines the error taxonomy for git-remote-cloak. Errors
// are classified and reported as what they are (auth vs network vs missing
// repository vs tamper vs rollback ...), fixing gcrypt's
// everything-is-"repository not found" behavior. Tamper and rollback alarms
// carry fixed, distinctive wordings so sync wrappers can escalate them
// instead of retrying.
package cloakerr

import (
	"errors"
	"fmt"
	"strings"
)

// Kind classifies an error for reporting and retry decisions.
type Kind int

const (
	// Auth: the transport rejected our credentials.
	Auth Kind = iota
	// Network: the host was unreachable or the connection failed.
	Network
	// RepoNotFound: the repository genuinely does not exist.
	RepoNotFound
	// Tamper: ciphertext failed AEAD/integrity verification, or remote
	// content contradicts the manifest. Never retried.
	Tamper
	// Rollback: the remote generation regressed. Never retried.
	Rollback
	// CASExhausted: the push lost the compare-and-swap race more times
	// than cloak.pushRetries allows.
	CASExhausted
	// LocalGit: a local git plumbing command failed.
	LocalGit
	// KeyUnavailable: the master key could not be loaded.
	KeyUnavailable
	// Crypto: producing ciphertext failed (encryption, key wrapping, or a
	// local I/O failure on the encrypt path). Distinct from Tamper, which is
	// a failure verifying or decrypting remote-supplied data.
	Crypto
	// Protocol: remote-supplied data authenticated under the key but could
	// not be understood (e.g. a manifest written by an incompatible version).
	// Distinct from Tamper: AEAD already verified the bytes, so this is a
	// version/format problem, not an attack.
	Protocol
	// TooLarge: an encrypted pack would exceed the host's per-file size limit
	// (cloak stores each pack as a single file). Raised pre-flight from the
	// configured cloak.maxPackBytes, or from the host's own rejection. Not an
	// attack and not retryable; the user must shrink what they push.
	TooLarge
)

// kindInfo holds the per-Kind reporting strings, indexed by Kind so the two
// reporting paths (String's short token and Error's user-facing prefix) share
// one source of truth: adding a Kind means adding one row here, not editing two
// parallel switches. The keyed literal pins each row to its constant, so the
// slice order cannot drift from the iota block above.
var kindInfo = [...]struct {
	token  string
	prefix string
}{
	Auth:           {"auth", "cloak: authentication failed"},
	Network:        {"network", "cloak: network failure"},
	RepoNotFound:   {"repo-not-found", "cloak: repository not found"},
	Tamper:         {"tamper", "cloak: TAMPER ALARM"},
	Rollback:       {"rollback", "cloak: ROLLBACK ALARM"},
	CASExhausted:   {"cas-exhausted", "cloak: concurrent-push retries exhausted"},
	LocalGit:       {"local-git", "cloak: local git failure"},
	KeyUnavailable: {"key-unavailable", "cloak: master key unavailable"},
	Crypto:         {"crypto", "cloak: cryptographic failure"},
	Protocol:       {"protocol", "cloak: incompatible remote"},
	TooLarge:       {"too-large", "cloak: pack too large for host"},
}

func (k Kind) String() string {
	if k >= 0 && int(k) < len(kindInfo) {
		return kindInfo[k].token
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// Error is a classified cloak error: Kind for decisions, Op for context,
// Err for the underlying cause (may be nil), and an optional Hint with an
// actionable next step rendered on its own line.
type Error struct {
	Kind Kind
	Op   string
	Err  error
	Hint string
	// custom, when non-empty, is returned verbatim by Error() instead of the
	// per-Kind prefix/op/hint composition. It lets a site hand-craft the entire
	// user-facing wording while still carrying a Kind for classification.
	custom string
}

func (e *Error) Error() string {
	if e.custom != "" {
		return e.custom
	}
	prefix := "cloak: error"
	if k := e.Kind; k >= 0 && int(k) < len(kindInfo) {
		prefix = kindInfo[k].prefix
	}
	msg := prefix
	if e.Op != "" {
		msg += ": " + e.Op
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	if e.Hint != "" {
		msg += "\n  hint: " + e.Hint
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// New wraps err as a classified Error.
func New(kind Kind, op string, err error) *Error {
	return &Error{Kind: kind, Op: op, Err: err}
}

// Newf builds a classified Error from a format string.
func Newf(kind Kind, op, format string, args ...any) *Error {
	return &Error{Kind: kind, Op: op, Err: fmt.Errorf(format, args...)}
}

// Newfh builds a classified Error from a format string and attaches an
// actionable hint, for sites that know both the message and the next step.
func Newfh(kind Kind, op, hint, format string, args ...any) *Error {
	return &Error{Kind: kind, Op: op, Err: fmt.Errorf(format, args...), Hint: hint}
}

// Newmsg builds a classified Error whose user-facing text is exactly msg (which
// should already begin with "cloak:"). Unlike Newf/Newfh it bypasses the
// per-Kind prefix and the op/hint composition, for the rare error whose
// multi-line wording is written end-to-end at the call site but still needs a
// Kind for classification and retry decisions.
func Newmsg(kind Kind, msg string) *Error {
	return &Error{Kind: kind, custom: msg}
}

// WithHint attaches an actionable next-step hint and returns e for chaining.
// Safe on a nil receiver. The hint renders on its own "  hint: ..." line.
func (e *Error) WithHint(hint string) *Error {
	if e != nil {
		e.Hint = hint
	}
	return e
}

// WithHintOn finds the *Error in err's chain and sets its hint when it has
// none, then returns err unchanged. It lets a caller annotate a classified
// error raised by a lower layer with context only the caller has (e.g. the
// engine marking an agecrypt Tamper as "this was the manifest"). No-op when
// err carries no *Error or a hint is already present.
func WithHintOn(err error, hint string) error {
	var ce *Error
	if errors.As(err, &ce) && ce.Hint == "" {
		ce.Hint = hint
	}
	return err
}

// Message returns the user-facing text for err, guaranteed to carry the
// "cloak:" prefix. Errors produced by this package already begin with it
// (see Error.Error); Message only prepends it for errors from elsewhere, so
// every reported failure reaches stderr under a uniform prefix.
func Message(err error) string {
	msg := err.Error()
	if !strings.HasPrefix(msg, "cloak:") {
		msg = "cloak: " + msg
	}
	return msg
}

// KindOf reports the classification of err, if it is (or wraps) an Error.
func KindOf(err error) (Kind, bool) {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Kind, true
	}
	return 0, false
}
