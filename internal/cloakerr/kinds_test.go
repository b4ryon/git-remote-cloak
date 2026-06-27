// Unit tests for the remaining taxonomy surface: Kind string forms, every
// Error() prefix wording, Newf formatting, and Unwrap.
package cloakerr

import (
	"errors"
	"strings"
	"testing"
)

func TestKindStrings(t *testing.T) {
	cases := map[Kind]string{
		Auth:           "auth",
		Network:        "network",
		RepoNotFound:   "repo-not-found",
		Tamper:         "tamper",
		Rollback:       "rollback",
		CASExhausted:   "cas-exhausted",
		LocalGit:       "local-git",
		KeyUnavailable: "key-unavailable",
		Crypto:         "crypto",
		Protocol:       "protocol",
		TooLarge:       "too-large",
		Kind(99):       "kind(99)",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", int(k), got, want)
		}
	}
}

func TestErrorPrefixes(t *testing.T) {
	cases := map[Kind]string{
		Auth:           "cloak: authentication failed",
		Network:        "cloak: network failure",
		RepoNotFound:   "cloak: repository not found",
		Tamper:         "cloak: TAMPER ALARM",
		Rollback:       "cloak: ROLLBACK ALARM",
		CASExhausted:   "cloak: concurrent-push retries exhausted",
		LocalGit:       "cloak: local git failure",
		KeyUnavailable: "cloak: master key unavailable",
		Crypto:         "cloak: cryptographic failure",
		Protocol:       "cloak: incompatible remote",
		TooLarge:       "cloak: pack too large for host",
		Kind(99):       "cloak: error",
	}
	for k, want := range cases {
		if got := New(k, "op", errors.New("cause")).Error(); !strings.HasPrefix(got, want) {
			t.Errorf("kind %v: Error() = %q, want prefix %q", k, got, want)
		}
	}
}

func TestErrorWithoutOpOrCause(t *testing.T) {
	if got := New(Network, "", nil).Error(); got != "cloak: network failure" {
		t.Fatalf("bare error = %q", got)
	}
	if got := New(Network, "fetch", nil).Error(); got != "cloak: network failure: fetch" {
		t.Fatalf("op-only error = %q", got)
	}
}

func TestNewfAndUnwrap(t *testing.T) {
	err := Newf(Rollback, "remote state", "generation %d < %d", 41, 42)
	if !strings.Contains(err.Error(), "generation 41 < 42") {
		t.Fatalf("Newf did not format: %q", err.Error())
	}
	cause := errors.New("inner")
	if got := New(Auth, "push", cause); !errors.Is(got, cause) {
		t.Fatal("Unwrap does not expose the cause")
	}
}
