// Package helper implements the git remote-helper side of git-remote-cloak:
// the line-oriented capabilities/option/list/fetch/push dialogue git speaks
// over stdin/stdout (gitremote-helpers(7)). The helper holds the per-remote
// flock for the whole invocation, validates remote state once per session
// (cached for the subsequent fetch/push batches), and reports errors with
// the cloak taxonomy on stderr. M2 implements capabilities/option/list/
// fetch; push lands in M3.
package helper

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/engine"
	"github.com/b4ryon/git-remote-cloak/internal/logx"
	"github.com/b4ryon/git-remote-cloak/internal/setup"
)

// capabilities advertised to git.
var capabilities = []string{"fetch", "push", "option"}

// session is the per-invocation state, initialized lazily on the first
// command that needs the repository or the remote.
type session struct {
	stderr io.Writer
	log    *slog.Logger

	remoteName string
	url        string

	sess *setup.Session
	eng  *engine.Engine
	rs   *engine.RemoteState

	verbosity int
	dryRun    bool
	forceAll  bool

	ready bool
}

// Main runs one helper invocation. args is git's (remote-name, URL) pair,
// or a single URL when the cloak:: URL is used directly.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "cloak: usage: git-remote-cloak <remote> <url>")
		return 2
	}
	s := &session{stderr: stderr, remoteName: args[0], url: args[len(args)-1]}
	s.log, _ = logx.Setup(logx.Options{Stderr: stderr, StderrLevel: slog.LevelWarn, Role: "helper"})
	defer s.cleanup()

	in := bufio.NewScanner(stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1<<20)
	out := bufio.NewWriter(stdout)
	defer out.Flush()

	for in.Scan() {
		line := in.Text()
		switch {
		case line == "capabilities":
			for _, c := range capabilities {
				fmt.Fprintln(out, c)
			}
			fmt.Fprintln(out)
			out.Flush()

		case strings.HasPrefix(line, "option "):
			fmt.Fprintln(out, s.option(strings.TrimPrefix(line, "option ")))
			out.Flush()

		case line == "list" || line == "list for-push":
			lines, err := s.list(line == "list for-push")
			if err != nil {
				return s.fatal(err)
			}
			for _, l := range lines {
				fmt.Fprintln(out, l)
			}
			fmt.Fprintln(out)
			out.Flush()

		case strings.HasPrefix(line, "fetch "):
			reqs := []string{strings.TrimPrefix(line, "fetch ")}
			for in.Scan() {
				l := in.Text()
				if l == "" {
					break
				}
				if !strings.HasPrefix(l, "fetch ") {
					return s.fatal(fmt.Errorf("protocol: unexpected %q inside fetch batch", l))
				}
				reqs = append(reqs, strings.TrimPrefix(l, "fetch "))
			}
			locks, err := s.fetchBatch(reqs)
			if err != nil {
				return s.fatal(err)
			}
			for _, lk := range locks {
				fmt.Fprintf(out, "lock %s\n", lk)
			}
			fmt.Fprintln(out)
			out.Flush()

		case strings.HasPrefix(line, "push "):
			specs := []string{strings.TrimPrefix(line, "push ")}
			for in.Scan() {
				l := in.Text()
				if l == "" {
					break
				}
				if !strings.HasPrefix(l, "push ") {
					return s.fatal(fmt.Errorf("protocol: unexpected %q inside push batch", l))
				}
				specs = append(specs, strings.TrimPrefix(l, "push "))
			}
			results, err := s.pushBatch(specs)
			if err != nil {
				return s.fatal(err)
			}
			for _, r := range results {
				if r.Err == "" {
					fmt.Fprintf(out, "ok %s\n", r.Dst)
				} else {
					fmt.Fprintf(out, "error %s %s\n", r.Dst, r.Err)
				}
			}
			fmt.Fprintln(out)
			out.Flush()

		case line == "":
			return 0

		default:
			return s.fatal(fmt.Errorf("protocol: unknown command %q", line))
		}
	}
	if err := in.Err(); err != nil {
		return s.fatal(fmt.Errorf("reading protocol stream: %w", err))
	}
	return 0
}

// fatal reports a classified error on stderr (the protocol-blessed path for
// fatal failures) and returns the exit code.
func (s *session) fatal(err error) int {
	msg := err.Error()
	if !strings.HasPrefix(msg, "cloak:") {
		msg = "cloak: " + msg
	}
	fmt.Fprintln(s.stderr, msg)
	// Point at the per-repo debug log for self-service troubleshooting. The
	// concrete path is only known once the session's state dir is open; before
	// that, name the conventional location.
	logPath := ".git/cloak/<remote>/log"
	if s.sess != nil && s.sess.St != nil {
		logPath = s.sess.St.LogPath()
	}
	fmt.Fprintln(s.stderr, "see the debug log for details: "+logPath)
	if s.log != nil {
		s.log.Error("fatal", "err", err.Error())
	}
	return 1
}

// option handles "option <name> <value>"; unknown options get the
// protocol-defined safe answer "unsupported".
func (s *session) option(rest string) string {
	name, value, _ := strings.Cut(rest, " ")
	switch name {
	case "verbosity":
		fmt.Sscanf(value, "%d", &s.verbosity)
		return "ok"
	case "progress":
		return "ok"
	case "dry-run":
		s.dryRun = value == "true"
		return "ok"
	case "force":
		s.forceAll = value == "true"
		return "ok"
	default:
		return "unsupported"
	}
}

// ensure lazily builds the full session (repo paths, config, key, state
// lock, per-repo logging, backend mirror, validated remote state).
func (s *session) ensure() error {
	if s.ready {
		return nil
	}
	sess, err := setup.Open(s.remoteName, s.url, s.stderr, "helper")
	if err != nil {
		return err
	}
	s.sess = sess
	s.eng = sess.Eng
	s.rs = sess.RS
	s.log = sess.Log
	s.ready = true
	return nil
}

// list produces the ref advertisement from the validated manifest. For
// "list for-push" the cached remote state additionally pins the CAS parent
// the push batch (M3) builds on.
func (s *session) list(forPush bool) ([]string, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if s.rs.Manifest == nil {
		return nil, nil // empty remote: just the terminating blank line
	}
	names := make([]string, 0, len(s.rs.Manifest.Refs))
	for name := range s.rs.Manifest.Refs {
		names = append(names, name)
	}
	sort.Strings(names)
	lines := make([]string, 0, len(names)+1)
	for _, name := range names {
		lines = append(lines, s.rs.Manifest.Refs[name]+" "+name)
	}
	if !forPush {
		if head := engine.HeadForList(s.rs.Manifest); head != "" {
			lines = append(lines, "@"+head+" HEAD")
		}
	}
	return lines, nil
}

// fetchBatch applies all missing manifest packs, then verifies every object
// git asked for is now present. Returns .keep lock lines for the protocol.
func (s *session) fetchBatch(reqs []string) ([]string, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	locks, err := s.eng.FetchApply(s.rs)
	if err != nil {
		return nil, err
	}
	for _, r := range reqs {
		oid, _, _ := strings.Cut(r, " ")
		if !s.eng.HaveObject(oid) {
			return nil, cloakerr.Newf(cloakerr.Tamper, "fetch verification",
				"object %s advertised by the manifest was not provided by any pack", oid)
		}
	}
	// Only now that packs are applied and every requested object is present
	// do the rollback and repo-identity pins advance.
	if err := s.eng.CommitPin(s.rs); err != nil {
		return nil, err
	}
	s.log.Info("fetch batch complete", "objects", len(reqs), "locks", len(locks))
	return locks, nil
}

// pushBatch parses the refspecs, runs the engine push against the remote
// state cached by "list for-push", and keeps the cached state current for
// any subsequent batch.
func (s *session) pushBatch(specs []string) ([]engine.RefResult, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	updates := make([]engine.RefUpdate, 0, len(specs))
	for _, spec := range specs {
		force := s.forceAll
		if strings.HasPrefix(spec, "+") {
			force = true
			spec = spec[1:]
		}
		src, dst, found := strings.Cut(spec, ":")
		if !found || dst == "" {
			return nil, fmt.Errorf("protocol: malformed push refspec %q", spec)
		}
		updates = append(updates, engine.RefUpdate{Src: src, Dst: dst, Force: force})
	}
	results, newRS, err := s.eng.Push(s.rs, updates, s.dryRun)
	if err != nil {
		return nil, err
	}
	s.rs = newRS
	return results, nil
}

func (s *session) cleanup() {
	if s.sess != nil {
		s.sess.Close()
	}
}
