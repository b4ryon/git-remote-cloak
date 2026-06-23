// Package logx configures structured logging for git-remote-cloak: a
// minimal stderr handler for operator-visible one-liners (git relays helper
// stderr inline) fanned out with a per-repo JSON debug log file under
// .git/cloak/<remote>/log, with size rotation and a per-invocation session
// id. Level resolution: CLOAK_LOG env wins, then cloak.logLevel config,
// then info (file) / warn (stderr).
//
// MUST never be logged, at any level: master key bytes, wrapped/derived
// file keys, HKDF outputs, decrypted pack bytes, file-content plaintext.
// The keystore Key type redacts itself in all formatters; plaintext flows
// only through io.Reader pipes, never through logged values.
//
// INTENTIONALLY allowed at debug level: ref names, object ids, pack ids,
// generation numbers. These are local metadata; the debug log lives inside
// the local .git, at the same trust level as the plaintext working tree,
// and they are essential for troubleshooting. The host (which must not see
// ref names) never receives the log. The security suite enforces the
// distinction: key material and file content are scanned for and must be
// absent; ref names are not.
package logx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// maxLogSize triggers rotation (one .1 generation kept).
const maxLogSize = 5 << 20

// ParseLevel maps a config/env string to a slog level.
func ParseLevel(s string, def slog.Level) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return slog.LevelError
	case "warn", "warning":
		return slog.LevelWarn
	case "info":
		return slog.LevelInfo
	case "debug":
		return slog.LevelDebug
	case "":
		return def
	default:
		return def
	}
}

// FileLevel resolves the file log level: CLOAK_LOG env over cloak.logLevel.
func FileLevel(cfgLevel string) slog.Level {
	if env := os.Getenv("CLOAK_LOG"); env != "" {
		return ParseLevel(env, slog.LevelInfo)
	}
	return ParseLevel(cfgLevel, slog.LevelInfo)
}

// Options configures Setup.
type Options struct {
	Stderr      io.Writer
	StderrLevel slog.Level
	FilePath    string // "" disables the file handler
	FileLevel   slog.Level
	Role        string // "helper" or "cli"
}

// Setup builds the fanout logger. The returned closer flushes/closes the
// log file; a file that cannot be opened silently disables file logging
// (the helper must never fail because of its log).
func Setup(o Options) (*slog.Logger, func()) {
	handlers := []slog.Handler{&stderrHandler{w: o.Stderr, min: o.StderrLevel}}
	closer := func() {}
	if o.FilePath != "" {
		rotate(o.FilePath)
		if f, err := os.OpenFile(o.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			// O_CREATE only applies 0600 to a freshly created file; tighten an
			// existing log (which may carry ref names / object ids) so it is
			// never group/world-readable. Best-effort: a Chmod failure leaves
			// the prior mode but must not disable logging.
			_ = f.Chmod(0o600)
			handlers = append(handlers, slog.NewJSONHandler(f, &slog.HandlerOptions{Level: o.FileLevel}))
			closer = func() { f.Close() }
		}
	}
	sid := make([]byte, 4)
	if _, err := rand.Read(sid); err != nil {
		copy(sid, []byte{0, 0, 0, 0})
	}
	lg := slog.New(fanout(handlers)).With("sid", hex.EncodeToString(sid), "role", o.Role)
	return lg, closer
}

func rotate(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogSize {
		_ = os.Rename(path, path+".1")
	}
}

// fanout dispatches each record to every child handler that accepts its level.
type fanout []slog.Handler

func (f fanout) Enabled(ctx context.Context, lvl slog.Level) bool {
	for _, h := range f {
		if h.Enabled(ctx, lvl) {
			return true
		}
	}
	return false
}

func (f fanout) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range f {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (f fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (f fanout) WithGroup(name string) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithGroup(name)
	}
	return out
}

// stderrHandler prints "cloak: <message> (k=v ...)" one-liners, the format
// git shows users inline. Groups are flattened; bookkeeping attrs (sid,
// role) are dropped from this human view.
type stderrHandler struct {
	w     io.Writer
	min   slog.Level
	attrs []slog.Attr
}

func (h *stderrHandler) Enabled(_ context.Context, lvl slog.Level) bool { return lvl >= h.min }

func (h *stderrHandler) Handle(_ context.Context, r slog.Record) error {
	var kv strings.Builder
	emit := func(a slog.Attr) {
		if a.Key == "sid" || a.Key == "role" {
			return
		}
		fmt.Fprintf(&kv, " %s=%v", a.Key, a.Value)
	}
	for _, a := range h.attrs {
		emit(a)
	}
	r.Attrs(func(a slog.Attr) bool { emit(a); return true })
	_, err := fmt.Fprintf(h.w, "cloak: %s%s\n", r.Message, kv.String())
	return err
}

func (h *stderrHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &stderrHandler{w: h.w, min: h.min, attrs: append(append([]slog.Attr{}, h.attrs...), attrs...)}
}

func (h *stderrHandler) WithGroup(string) slog.Handler { return h }
