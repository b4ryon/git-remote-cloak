// Package setup constructs a ready cloak session, shared by the remote
// helper and the git-cloak operator commands: repository path resolution,
// SHA-1 object-format check, cloak.* config, master key, per-remote state
// directory with its flock, per-repo file logging, the backend mirror, and
// the validated remote state (fetch + AEAD + rollback pin).
package setup

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/config"
	"github.com/b4ryon/git-remote-cloak/internal/engine"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/logx"
	"github.com/b4ryon/git-remote-cloak/internal/state"
)

// helperURLRe matches git's remote-helper transport syntax (<word>::...),
// e.g. "ext::", "fd::", or a nested "cloak::". After stripping the cloak::
// prefix the backend URL must be a real transport (https/ssh/git/file,
// scp-like SSH, or a local path) and never another helper, so a malicious
// "cloak::ext::sh -c ..." cannot reach git's arbitrary-command transports.
var helperURLRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+.-]*::`)

// Session is a fully wired engine plus validated remote state. Close
// releases the state lock and the log file.
type Session struct {
	G   *gitx.G
	Eng *engine.Engine
	RS  *engine.RemoteState
	Log *slog.Logger
	Cfg config.Config
	St  *state.Dir

	closers []func()
}

// Close releases resources in reverse order.
func (s *Session) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
}

// Open builds the session and validates the remote (fetch + AEAD +
// rollback pin). url may be empty, in which case it is resolved from
// remote.<remoteName>.url and must use the cloak:: scheme (the helper
// passes the url git gave it; CLI commands pass "").
func Open(remoteName, url string, stderr io.Writer, role string) (*Session, error) {
	s, err := OpenLocal(remoteName, url, stderr, role)
	if err != nil {
		return nil, err
	}
	if err := s.LoadRemote(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// LoadRemote fetches and validates the remote state into s.RS.
func (s *Session) LoadRemote() error {
	rs, err := s.Eng.LoadRemoteState()
	if err != nil {
		return err
	}
	s.RS = rs
	return nil
}

// OpenLocal wires everything local (paths, config, key, state lock,
// logging, backend mirror, engine) WITHOUT touching the remote. Used by
// accept-rollback, which must clear the pin before any validation runs.
func OpenLocal(remoteName, url string, stderr io.Writer, role string) (*Session, error) {
	boot, _ := logx.Setup(logx.Options{Stderr: stderr, StderrLevel: slog.LevelWarn, Role: role})
	g := gitx.New(boot)

	gd := os.Getenv("GIT_DIR")
	localGitDir, err := g.Out(gitx.Opts{GitDir: gd}, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "resolve git dir", err)
	}
	common, err := g.Out(gitx.Opts{GitDir: localGitDir}, "rev-parse", "--git-common-dir")
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "resolve git common dir", err)
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(localGitDir, common)
	}
	common = filepath.Clean(common)

	if format, err := g.Out(gitx.Opts{GitDir: localGitDir}, "rev-parse", "--show-object-format"); err == nil && format != "sha1" {
		return nil, cloakerr.Newf(cloakerr.LocalGit, "object format",
			"%s repositories are not supported in v0 (sha1 only)", format)
	}

	cfg, err := config.Load(g, localGitDir)
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "read cloak config", err)
	}
	if url == "" {
		raw, err := g.Out(gitx.Opts{GitDir: localGitDir}, "config", "--get", "remote."+remoteName+".url")
		if err != nil {
			return nil, cloakerr.Newf(cloakerr.LocalGit, "resolve remote",
				"remote %q has no configured URL", remoteName)
		}
		if !strings.HasPrefix(raw, "cloak::") {
			return nil, cloakerr.Newf(cloakerr.LocalGit, "resolve remote",
				"remote %q is not a cloak:: remote (url %q)", remoteName, raw)
		}
		url = raw
	}
	url = strings.TrimPrefix(url, "cloak::")
	if url == "" {
		return nil, cloakerr.Newf(cloakerr.LocalGit, "resolve remote",
			"empty backend URL after the cloak:: prefix")
	}
	if helperURLRe.MatchString(url) {
		return nil, cloakerr.Newf(cloakerr.LocalGit, "validate remote transport",
			"refusing remote-helper transport in backend URL %q (cloak does not allow ext::/fd:: or nested helpers)", url)
	}

	key, err := keystore.Load(cfg.KeyRef)
	if err != nil {
		// Name the actual ref in play so the file backend (and a misconfigured
		// keyRef on any platform) gives a recovery path, not a bare OS error.
		return nil, cloakerr.WithHintOn(err, fmt.Sprintf(
			"cloak.keyRef is %q for this repo; verify it points at your key, then run `git cloak keygen` (first machine) or `git cloak key import` (a new machine)", cfg.KeyRef))
	}

	st, err := state.Open(common, remoteName, url)
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "open state dir", err)
	}
	unlock, err := st.Lock()
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "lock state dir", err)
	}
	s := &Session{G: g, Cfg: cfg, St: st}
	// Release the lock (logging a failed unlock/close instead of dropping it)
	// then best-effort wipe the master key bytes when the session ends (see
	// keystore.Key.Wipe for the Go limitation).
	s.closers = []func(){
		func() {
			if err := unlock(); err != nil && s.Log != nil {
				s.Log.Warn("releasing state lock failed", "err", err)
			}
		},
		key.Wipe,
	}

	lg, closeLog := logx.Setup(logx.Options{
		Stderr:      stderr,
		StderrLevel: slog.LevelWarn,
		FilePath:    st.LogPath(),
		FileLevel:   logx.FileLevel(cfg.LogLevel),
		Role:        role,
	})
	s.Log = lg.With("remote", remoteName)
	s.closers = append(s.closers, closeLog)
	g.SetLogger(s.Log)
	s.Log.Info("session start", "url", url, "keyid", key.ID(), "branch", cfg.Branch)

	be, err := backend.Open(g, st.BackendGitDir(), url, cfg.Branch, s.Log)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.Eng = &engine.Engine{
		G: g, LocalGitDir: localGitDir, St: st, Be: be,
		Key: key, Cfg: cfg, Log: s.Log,
	}
	return s, nil
}
