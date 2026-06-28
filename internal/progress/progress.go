// Package progress renders a lightweight, single-line braille progress
// indicator on a writer (cloak's stderr) so a slow `git push`/`git fetch`
// shows a live "still working" cue with the current phase and elapsed time.
// It is purely cosmetic: it never touches the remote-helper stdout protocol,
// the on-disk/on-wire format, or the crypto. When disabled - the writer is not
// a terminal, or git did not ask for progress - it is inert, so
// non-interactive runs (launchd, cron, pipes, --quiet) print nothing.
//
// The Spinner also implements io.Writer: the helper routes ALL of its stderr
// (logs and error messages) through it, so any such output erases a live
// indicator line first and never glues onto it. Output from git itself (a
// separate process writing the same terminal) cannot be intercepted, so the
// helper additionally clears the indicator before handing control back to git.
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
// smooth single-cell indicator used by tools like opencode. The glyphs are
// literal UTF-8; a terminal that lacks braille glyphs is the user's font
// problem, not a correctness one, since the indicator is cosmetic.
var frames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

// interval is the redraw period; ~100ms reads as smooth without busy-spinning.
const interval = 100 * time.Millisecond

// clearLine returns the cursor to column 0 and erases to end of line.
const clearLine = "\r\033[K"

// Spinner animates a one-line "<braille> <label>  <elapsed>" status on out, and
// proxies plain writes to out (clearing the live line first). The zero value is
// not usable; construct with New. A nil *Spinner is a valid no-op receiver.
type Spinner struct {
	out   io.Writer
	isTTY bool

	mu      sync.Mutex
	want    bool // git's "option progress"; default true (animate when on a TTY)
	label   string
	started time.Time
	running bool
	stop    chan struct{}
	done    chan struct{}
}

// New returns a Spinner over out (cloak's real terminal stderr). It animates
// only when out is a terminal and progress is wanted (see SetWant; wanted by
// default). Route the helper's stderr through the returned Spinner via Write so
// log and error output never collides with a live indicator line.
func New(out io.Writer) *Spinner {
	return &Spinner{out: out, isTTY: isTerminal(out), want: true}
}

// isTerminal reports whether w is a real, non-dumb TTY (an *os.File backed by
// one). The indicator needs carriage-return / erase-line control sequences to
// redraw in place, so a non-terminal or TERM=dumb writer disables animation.
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

// SetWant enables or disables the animation, mirroring git's "option progress".
// It does not affect passthrough Write.
func (s *Spinner) SetWant(want bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.want = want
	s.mu.Unlock()
}

// Write proxies p to the underlying writer, first erasing any live indicator
// line so log or error output never glues onto it; the animation repaints on
// its next tick. Implementing io.Writer lets the helper send all of its stderr
// through the Spinner.
func (s *Spinner) Write(p []byte) (int, error) {
	if s == nil {
		return len(p), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		fmt.Fprint(s.out, clearLine)
	}
	return s.out.Write(p)
}

// Phase sets the status label, starting the animation on first use when
// enabled. Later calls just change the label; the elapsed clock keeps running
// from the first Phase so the user sees total operation time.
func (s *Spinner) Phase(label string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.isTTY || !s.want {
		return
	}
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
	if s == nil {
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
// clears the line and signals done.
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

// draw paints one frame in place (no trailing newline) under the mutex, so it
// never interleaves with a concurrent passthrough Write.
func (s *Spinner) draw(i int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	frame := frames[i%len(frames)]
	fmt.Fprintf(s.out, "%s%c %s  %s", clearLine, frame, s.label, humanDuration(time.Since(s.started)))
}

// clear erases the indicator line and returns the cursor to column 0.
func (s *Spinner) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprint(s.out, clearLine)
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
