// Unit tests for the spinner: disabled spinners stay silent, a nil receiver is
// safe, the enabled animation draws the label plus a braille frame and clears
// the line on stop, and the elapsed-time formatter is correct.
package progress

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuf is a concurrency-safe capture target, since the animation writes
// from its own goroutine while the test reads.
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// TestDisabledIsSilent: New over a non-terminal writer yields a disabled
// spinner that prints nothing, the launchd/cron/pipe behavior we rely on.
func TestDisabledIsSilent(t *testing.T) {
	var b lockedBuf
	s := New(&b, true) // *lockedBuf is not an *os.File TTY -> disabled
	s.Phase("working")
	time.Sleep(150 * time.Millisecond)
	s.Stop()
	if got := b.String(); got != "" {
		t.Fatalf("disabled spinner wrote %q, want nothing", got)
	}
}

// TestNilSpinnerNoPanic: a nil *Spinner is a valid no-op receiver.
func TestNilSpinnerNoPanic(t *testing.T) {
	var s *Spinner
	s.Phase("x")
	s.Stop()
}

// TestEnabledDrawsAndClears bypasses the TTY gate (no terminal under `go test`)
// to exercise the animation: it must show the label, render a braille frame,
// and clear the line when stopped.
func TestEnabledDrawsAndClears(t *testing.T) {
	var b lockedBuf
	s := &Spinner{w: &b, enabled: true}
	s.Phase("uploading")
	time.Sleep(250 * time.Millisecond)
	s.Phase("uploading to host") // relabel mid-flight keeps animating
	time.Sleep(150 * time.Millisecond)
	s.Stop()

	out := b.String()
	if !strings.Contains(out, "uploading to host") {
		t.Fatalf("output missing relabeled phase: %q", out)
	}
	if !strings.ContainsAny(out, string(frames)) {
		t.Fatalf("output missing a braille frame: %q", out)
	}
	if !strings.HasSuffix(out, "\r\033[K") {
		t.Fatalf("output not cleared on stop: %q", out)
	}
}

// TestStopIdempotent: Stop before Phase, and double Stop, must not panic or hang.
func TestStopIdempotent(t *testing.T) {
	s := &Spinner{w: &lockedBuf{}, enabled: true}
	s.Stop() // never started
	s.Phase("go")
	s.Stop()
	s.Stop() // second stop
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{5 * time.Second, "5s"},
		{59 * time.Second, "59s"},
		{60 * time.Second, "1m00s"},
		{75 * time.Second, "1m15s"},
		{6*time.Minute + 12*time.Second, "6m12s"},
	}
	for _, c := range cases {
		if got := humanDuration(c.d); got != c.want {
			t.Errorf("humanDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
