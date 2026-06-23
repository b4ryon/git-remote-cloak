// Package gitx runs git subprocesses for cloak with a controlled
// environment, captured stderr, duration logging, and typed errors that the
// error-taxonomy classifier (M5) consumes. Every git invocation in the
// helper and engine goes through this package.
package gitx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// defaultGitTimeout bounds a git invocation when no context is supplied and
// the call is not interactive, so a dead or stalled host cannot hang the
// helper (and the user's git) indefinitely.
const defaultGitTimeout = 120 * time.Second

// defaultTimeout resolves the per-invocation deadline. CLOAK_GIT_TIMEOUT
// overrides it with a Go duration (e.g. "30s", "5m"); "0" or "off" disables
// the deadline. An unparseable value falls back to the default.
func defaultTimeout() time.Duration {
	v := strings.TrimSpace(os.Getenv("CLOAK_GIT_TIMEOUT"))
	switch {
	case v == "":
		return defaultGitTimeout
	case v == "0" || strings.EqualFold(v, "off"):
		return 0
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return defaultGitTimeout
}

// G runs git commands. The logger is swappable so the helper can upgrade
// from a bootstrap stderr logger to the per-repo file logger once the state
// directory is known.
type G struct {
	log *slog.Logger
}

// New returns a runner logging through lg.
func New(lg *slog.Logger) *G { return &G{log: lg} }

// SetLogger swaps the logger (used after the per-repo log file opens).
func (g *G) SetLogger(lg *slog.Logger) { g.log = lg }

// Opts controls one git invocation.
type Opts struct {
	// Dir is the process working directory ("" = inherit).
	Dir string
	// GitDir sets GIT_DIR explicitly; "" removes it from the environment
	// so the command resolves the repo from Dir.
	GitDir string
	// Env appends extra KEY=VAL pairs.
	Env []string
	// Scrub disables system/global git config; used for object building in
	// the private backend repo so user config cannot interfere. Network
	// operations are NOT scrubbed (user transport config like
	// core.sshCommand must keep working).
	Scrub bool
	// Stdin streams to the command if non-nil.
	Stdin io.Reader
	// Stdout streams from the command if non-nil; otherwise captured.
	Stdout io.Writer
	// Ctx, when non-nil, bounds the invocation; on expiry the process is
	// killed and Run returns a *TimeoutError (or *CanceledError on cancel).
	Ctx context.Context
	// Interactive marks an invocation that may prompt on the tty (credential
	// or passphrase entry); no default timeout is imposed so a human prompt
	// is not killed. Ignored when Ctx is set.
	Interactive bool
}

// GitError is a non-zero git exit with its captured stderr.
type GitError struct {
	Args     []string
	ExitCode int
	Stderr   string
}

func (e *GitError) Error() string {
	s := strings.TrimSpace(e.Stderr)
	if s == "" {
		s = "(no stderr)"
	}
	return fmt.Sprintf("git %s: exit %d: %s", strings.Join(e.Args, " "), e.ExitCode, s)
}

// TimeoutError is returned when a git invocation exceeded its deadline and
// was killed. ClassifyTransport maps it to cloakerr.Network so a stalled host
// is never mistaken for tamper.
type TimeoutError struct {
	Args    []string
	Elapsed time.Duration
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("git %s: timed out after %s", strings.Join(e.Args, " "), e.Elapsed)
}

// CanceledError is returned when a git invocation's context was canceled.
type CanceledError struct{ Args []string }

func (e *CanceledError) Error() string {
	return fmt.Sprintf("git %s: canceled", strings.Join(e.Args, " "))
}

// resolveContext picks the deadline context for one invocation. It returns a
// cancel func that is always safe to defer: a no-op when o.Ctx is supplied or
// no deadline applies, the real WithTimeout cancel otherwise.
func resolveContext(o Opts) (context.Context, context.CancelFunc) {
	if o.Ctx != nil {
		return o.Ctx, func() {}
	}
	if d := defaultTimeout(); d > 0 && !o.Interactive {
		return context.WithTimeout(context.Background(), d)
	}
	return context.Background(), func() {}
}

// buildEnv assembles the child process environment: the parent environment
// with any inherited GIT_DIR dropped, then GIT_DIR/scrub/extra pairs applied
// per o.
func buildEnv(o Opts) []string {
	env := make([]string, 0, len(os.Environ())+4)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_DIR=") {
			continue
		}
		env = append(env, kv)
	}
	if o.GitDir != "" {
		env = append(env, "GIT_DIR="+o.GitDir)
	}
	if o.Scrub {
		env = append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	}
	return append(env, o.Env...)
}

// classifyExit maps a finished invocation to its typed error (nil on success).
// A deadline/cancel kills the process, so it is surfaced as a *TimeoutError or
// *CanceledError; the classifier then reports network (a stall), never tamper.
func classifyExit(args []string, ctxErr, runErr error, exit int, dur time.Duration, stderr string) error {
	if runErr == nil {
		return nil
	}
	switch ctxErr {
	case context.DeadlineExceeded:
		return &TimeoutError{Args: args, Elapsed: dur}
	case context.Canceled:
		return &CanceledError{Args: args}
	}
	if exit == -1 {
		return fmt.Errorf("git %s: %w", strings.Join(args, " "), runErr)
	}
	return &GitError{Args: args, ExitCode: exit, Stderr: stderr}
}

// Run executes git with args. Returns captured stdout (when not streamed)
// and the captured stderr; err is *GitError on non-zero exit.
func (g *G) Run(o Opts, args ...string) (stdout, stderr string, err error) {
	ctx, cancel := resolveContext(o)
	defer cancel()
	// Refuse git's arbitrary-command transports (ext::, fd::) on every git
	// invocation as defense in depth behind setup's URL validation, so a
	// malicious cloak:: URL cannot reach them. Harmless for local plumbing.
	gitArgs := append([]string{
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.fd.allow=never",
	}, args...)
	cmd := exec.CommandContext(ctx, "git", gitArgs...)
	cmd.Dir = o.Dir
	cmd.Env = buildEnv(o)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdin = o.Stdin
	if o.Stdout != nil {
		cmd.Stdout = o.Stdout
	} else {
		cmd.Stdout = &outBuf
	}
	cmd.Stderr = &errBuf

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)

	stdout = outBuf.String()
	stderr = errBuf.String()
	exit := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			exit = -1
		}
	}
	if g.log != nil {
		g.log.Debug("git", "args", strings.Join(args, " "), "dir", o.Dir,
			"gitdir", o.GitDir, "exit", exit, "ms", dur.Milliseconds(),
			"stderr_bytes", len(stderr))
	}
	return stdout, stderr, classifyExit(args, ctx.Err(), runErr, exit, dur, stderr)
}

// Out runs git and returns whitespace-trimmed stdout.
func (g *G) Out(o Opts, args ...string) (string, error) {
	stdout, _, err := g.Run(o, args...)
	return strings.TrimSpace(stdout), err
}
