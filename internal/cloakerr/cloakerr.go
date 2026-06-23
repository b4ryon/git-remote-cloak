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
)

func (k Kind) String() string {
	switch k {
	case Auth:
		return "auth"
	case Network:
		return "network"
	case RepoNotFound:
		return "repo-not-found"
	case Tamper:
		return "tamper"
	case Rollback:
		return "rollback"
	case CASExhausted:
		return "cas-exhausted"
	case LocalGit:
		return "local-git"
	case KeyUnavailable:
		return "key-unavailable"
	case Crypto:
		return "crypto"
	case Protocol:
		return "protocol"
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
}

func (e *Error) Error() string {
	var prefix string
	switch e.Kind {
	case Auth:
		prefix = "cloak: authentication failed"
	case Network:
		prefix = "cloak: network failure"
	case RepoNotFound:
		prefix = "cloak: repository not found"
	case Tamper:
		prefix = "cloak: TAMPER ALARM"
	case Rollback:
		prefix = "cloak: ROLLBACK ALARM"
	case CASExhausted:
		prefix = "cloak: concurrent-push retries exhausted"
	case LocalGit:
		prefix = "cloak: local git failure"
	case KeyUnavailable:
		prefix = "cloak: master key unavailable"
	case Crypto:
		prefix = "cloak: cryptographic failure"
	case Protocol:
		prefix = "cloak: incompatible remote"
	default:
		prefix = "cloak: error"
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

// KindOf reports the classification of err, if it is (or wraps) an Error.
func KindOf(err error) (Kind, bool) {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Kind, true
	}
	return 0, false
}
