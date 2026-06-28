// Package progress renders a lightweight, single-line braille spinner on a
// writer (cloak's stderr) so a slow `git push`/`git fetch` shows a live
// "still working" cue with the current phase and elapsed time. It is purely
// cosmetic: it never touches the remote-helper stdout protocol, the
// on-disk/on-wire format, or the crypto. When disabled - the writer is not a
// terminal, or git did not ask for progress - every method is a no-op, so
// non-interactive runs (launchd, cron, pipes, --quiet) print nothing.
package progress

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
)

// frames is the 10-step braille "dots" wheel (Unicode U+280B..U+280F) - the
// smooth single-cell spinner used by tools like opencode. The glyphs are
// literal UTF-8; a terminal that lacks braille glyphs is the user's font
// problem, not a correctness one, since the spinner is cosmetic.
var frames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

// interval is the redraw period; ~100ms reads as smooth without busy-spinning.
const interval = 100 * time.Millisecond

// Spinner animates a one-line "<braille> <label>  <elapsed>" status on w. The
// zero value is not usable; construct with New. A nil *Spinner is a valid
// no-op receiver, so callers need not branch on whether progress is wanted.
type Spinner struct {
	w       io.Writer
	enabled bool

	mu      sync.Mutex
	label   string
	started time.Time
	running bool
	stop    chan struct{}
	done    chan struct{}
}

// New returns a Spinner that draws to w only when want is true AND w is a
// terminal; otherwise it returns a disabled spinner whose methods all no-op.
func New(w io.Writer, want bool) *Spinner {
	return &Spinner{w: w, enabled: want && isTerminal(w)}
}

// isTerminal reports whether w is a real TTY (an *os.File backed by one). A
// non-dumb terminal is required because the spinner uses carriage-return and
// erase-line control sequences to redraw in place.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// Phase sets the status label shown next to the spinner, starting the animation
// on first use. Subsequent calls just change the label; the elapsed clock keeps
// running from the first Phase so the user sees total operation time.
func (s *Spinner) Phase(label string) {
	if s == nil || !s.enabled {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.label = label
	if s.running {
		return
	}
	s.running = true
	s.started = time.Now()
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	go s.loop(s.stop, s.done)
}

// Stop ends the animation and clears the line, leaving the cursor at column 0
// so the next writer (git's own push/fetch summary) starts clean. Safe to call
// repeatedly and when never started.
func (s *Spinner) Stop() {
	if s == nil || !s.enabled {
		return
	}
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	stop, done := s.stop, s.done
	s.mu.Unlock()
	close(stop)
	<-done
}

// loop redraws the current frame every interval until stop is closed, then
// clears the line and signals done. It owns no state beyond the frame index;
// the label and start time are read under the mutex in draw.
func (s *Spinner) loop(stop, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(interval)
	defer t.Stop()
	i := 0
	s.draw(i) // paint immediately so the first phase shows without a tick's delay
	for {
		select {
		case <-stop:
			s.clear()
			return
		case <-t.C:
			i++
			s.draw(i)
		}
	}
}

// draw paints one frame: "\r" to column 0, erase-to-end-of-line, then the
// glyph, label, and elapsed time, with no trailing newline so the line is
// overwritten in place on the next tick.
func (s *Spinner) draw(i int) {
	s.mu.Lock()
	label, started := s.label, s.started
	s.mu.Unlock()
	frame := frames[i%len(frames)]
	fmt.Fprintf(s.w, "\r\033[K%c %s  %s", frame, label, humanDuration(time.Since(started)))
}

// clear erases the spinner line and returns the cursor to column 0.
func (s *Spinner) clear() {
	fmt.Fprint(s.w, "\r\033[K")
}

// humanDuration renders elapsed time compactly: "5s" under a minute, "1m05s"
// beyond it.
func humanDuration(d time.Duration) string {
	sec := int(d.Seconds())
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	return fmt.Sprintf("%dm%02ds", sec/60, sec%60)
}
