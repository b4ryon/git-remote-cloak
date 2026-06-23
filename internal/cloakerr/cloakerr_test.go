// Unit tests for the error taxonomy: fixed alarm wordings and Kind
// extraction through wrapping.
package cloakerr

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAlarmWordings(t *testing.T) {
	if got := New(Tamper, "decrypt manifest", errors.New("boom")).Error(); !strings.HasPrefix(got, "cloak: TAMPER ALARM:") {
		t.Fatalf("tamper wording = %q", got)
	}
	if got := New(Rollback, "fetch", errors.New("gen 41 < 42")).Error(); !strings.HasPrefix(got, "cloak: ROLLBACK ALARM:") {
		t.Fatalf("rollback wording = %q", got)
	}
	if got := New(Auth, "push", errors.New("denied")).Error(); !strings.Contains(got, "authentication failed") {
		t.Fatalf("auth wording = %q", got)
	}
}

func TestHintRendering(t *testing.T) {
	got := New(Tamper, "decrypt header", errors.New("boom")).WithHint("check your key").Error()
	if !strings.HasPrefix(got, "cloak: TAMPER ALARM: decrypt header: boom") {
		t.Fatalf("hint changed the base message: %q", got)
	}
	if !strings.Contains(got, "\n  hint: check your key") {
		t.Fatalf("hint line missing: %q", got)
	}
	// No hint => no trailing hint line.
	if strings.Contains(New(Network, "fetch", nil).Error(), "hint:") {
		t.Fatal("hint line emitted for an error with no hint")
	}
}

func TestWithHintOn(t *testing.T) {
	// Common case: the error IS an *Error (what the engine call sites pass).
	direct := WithHintOn(New(Tamper, "decrypt", errors.New("boom")), "first hint")
	if !strings.Contains(direct.Error(), "  hint: first hint") {
		t.Fatalf("WithHintOn did not annotate a direct *Error: %q", direct.Error())
	}
	// Through wrapping: it finds and mutates the inner *Error. (fmt.Errorf
	// caches its rendered string, so verify via extraction, not the outer
	// .Error().)
	wrapped := fmt.Errorf("outer: %w", New(Tamper, "decrypt", errors.New("boom")))
	WithHintOn(wrapped, "inner hint")
	var ce *Error
	if !errors.As(wrapped, &ce) || ce.Hint != "inner hint" {
		t.Fatalf("WithHintOn did not set the wrapped *Error hint: %+v", ce)
	}
	// Idempotent: a second call must not overwrite an existing hint.
	WithHintOn(direct, "second hint")
	if strings.Contains(direct.Error(), "second hint") {
		t.Fatal("WithHintOn overwrote an existing hint")
	}
	// No *Error in chain => unchanged.
	plain := errors.New("plain")
	if WithHintOn(plain, "x") != plain {
		t.Fatal("WithHintOn altered a plain error")
	}
}

func TestKindOfThroughWrapping(t *testing.T) {
	err := fmt.Errorf("outer: %w", New(Network, "fetch", errors.New("timeout")))
	kind, ok := KindOf(err)
	if !ok || kind != Network {
		t.Fatalf("KindOf = %v, %v", kind, ok)
	}
	if _, ok := KindOf(errors.New("plain")); ok {
		t.Fatal("KindOf matched a plain error")
	}
}
