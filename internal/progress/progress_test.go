// Unit tests for the progress indicator: disabled indicators stay silent, a nil
// receiver is safe, the enabled animation draws the label plus a braille frame
// and clears the line on stop, passthrough writes erase a live line first, and
// the elapsed-time formatter is correct.
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

// TestDisabledIsSilent: New over a non-terminal writer yields an indicator that
// does not animate, the launchd/cron/pipe behavior we rely on.
func TestDisabledIsSilent(t *testing.T) {
	var b lockedBuf
	s := New(&b) // *lockedBuf is not an *os.File TTY -> animation disabled
	s.Phase("working")
	time.Sleep(150 * time.Millisecond)
	s.Stop()
	if got := b.String(); got != "" {
		t.Fatalf("disabled indicator wrote %q, want nothing", got)
	}
}

// TestDisabledWriteIsPlainPassthrough: when not animating, Write must not inject
// any control sequences.
func TestDisabledWriteIsPlainPassthrough(t *testing.T) {
	var b lockedBuf
	s := New(&b)
	if _, err := s.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != "hello\n" {
		t.Fatalf("passthrough wrote %q, want %q", got, "hello\n")
	}
}

// TestNilSpinnerNoPanic: a nil *Spinner is a valid no-op receiver.
func TestNilSpinnerNoPanic(t *testing.T) {
	var s *Spinner
	s.Phase("x")
	s.SetWant(true)
	if n, err := s.Write([]byte("x")); n != 1 || err != nil {
		t.Fatalf("nil Write = (%d,%v), want (1,nil)", n, err)
	}
	s.Stop()
}

// TestEnabledDrawsAndClears bypasses the TTY gate (no terminal under `go test`)
// to exercise the animation: it must show the label, render a braille frame,
// and clear the line when stopped.
func TestEnabledDrawsAndClears(t *testing.T) {
	var b lockedBuf
	s := &Spinner{out: &b, isTTY: true, want: true}
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
	if !strings.HasSuffix(out, clearLine) {
		t.Fatalf("output not cleared on stop: %q", out)
	}
}

// TestWriteClearsBeforePassthrough: a log line written while the indicator is
// live must be preceded by a line-clear, so it never glues onto a frame.
func TestWriteClearsBeforePassthrough(t *testing.T) {
	var b lockedBuf
	s := &Spinner{out: &b, isTTY: true, want: true}
	s.Phase("working")
	time.Sleep(150 * time.Millisecond)
	if _, err := s.Write([]byte("WARN something\n")); err != nil {
		t.Fatal(err)
	}
	s.Stop()
	out := b.String()
	if !strings.Contains(out, clearLine+"WARN something\n") {
		t.Fatalf("log line not preceded by a clear (would glue): %q", out)
	}
}

// TestStopIdempotent: Stop before Phase, and double Stop, must not panic or hang.
func TestStopIdempotent(t *testing.T) {
	s := &Spinner{out: &lockedBuf{}, isTTY: true, want: true}
	s.Stop() // never started
	s.Phase("go")
	s.Stop()
	s.Stop() // second stop
}

// TestWantGatesAnimation: SetWant(false) (git --no-progress) keeps a TTY-backed
// indicator silent.
func TestWantGatesAnimation(t *testing.T) {
	var b lockedBuf
	s := &Spinner{out: &b, isTTY: true, want: true}
	s.SetWant(false)
	s.Phase("working")
	time.Sleep(150 * time.Millisecond)
	s.Stop()
	if got := b.String(); got != "" {
		t.Fatalf("SetWant(false) still animated: %q", got)
	}
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
