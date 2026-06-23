// git-cloak status and accept-rollback: operator visibility into the
// remote (generation, packs, applied state, rollback pin) and the
// explicit, one-shot acceptance of a remote generation regression.
package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/b4ryon/git-remote-cloak/internal/setup"
	"github.com/b4ryon/git-remote-cloak/internal/userpresence"
)

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	remote := fs.String("remote", "origin", "cloak remote to inspect")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sess, err := setup.Open(*remote, "", stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()

	fmt.Fprintf(stdout, "Remote:     %s\n", *remote)
	fmt.Fprintf(stdout, "Key:        %s (%s)\n", sess.Eng.Key.ID(), sess.Cfg.KeyRef)
	if sess.RS.Manifest == nil {
		fmt.Fprintln(stdout, "State:      empty (no backend branch yet; first push creates it)")
		return 0
	}
	m := sess.RS.Manifest
	var total, largest, smallest int64
	smallest = -1
	for _, p := range m.Packs {
		total += p.Size
		if p.Size > largest {
			largest = p.Size
		}
		if smallest < 0 || p.Size < smallest {
			smallest = p.Size
		}
	}
	applied, err := sess.St.AppliedSet()
	if err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	appliedLive := 0
	for _, p := range m.Packs {
		if applied[p.ID] {
			appliedLive++
		}
	}
	pin, pinned, _ := sess.St.LoadPin()
	if pinned {
		fmt.Fprintf(stdout, "Generation: %d (last verified on this machine: %d, manifest %.12s)\n", m.Generation, pin.Generation, pin.ManifestHash)
	} else {
		fmt.Fprintf(stdout, "Generation: %d (nothing verified on this machine yet)\n", m.Generation)
	}
	if rid, ok, _ := sess.St.LoadRepoID(); ok {
		note := "matches this machine's record"
		if rid != m.RepoID {
			note = "DIFFERS from this machine's record"
		}
		fmt.Fprintf(stdout, "Repo-ID:    %s (%s)\n", m.RepoID, note)
	} else {
		fmt.Fprintf(stdout, "Repo-ID:    %s (no record on this machine yet)\n", m.RepoID)
	}
	fmt.Fprintf(stdout, "Head:       %s\n", m.Head)
	fmt.Fprintf(stdout, "Refs:       %d\n", len(m.Refs))
	fmt.Fprintf(stdout, "Packs:      %d live, %d bytes total (largest %d, smallest %d)\n",
		len(m.Packs), total, largest, smallest)
	fmt.Fprintf(stdout, "Applied:    %d of %d live packs already indexed on this machine\n", appliedLive, len(m.Packs))
	switch {
	case pinned && m.Generation > pin.Generation:
		fmt.Fprintln(stdout, "Sync:       remote is ahead of this machine; run `git pull` to catch up")
	case pinned:
		fmt.Fprintln(stdout, "Sync:       up to date with the remote")
	default:
		fmt.Fprintln(stdout, "Sync:       first contact (run `git pull` to fetch and pin the remote)")
	}
	return 0
}

func cmdAcceptRollback(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("accept-rollback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	remote := fs.String("remote", "origin", "cloak remote to accept the regression for")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := userpresence.Require("accept rollback on remote "+*remote, stderr); err != nil {
		return cliFail(stderr, err)
	}
	sess, err := setup.OpenLocal(*remote, "", stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()

	if pin, ok, _ := sess.St.LoadPin(); ok {
		fmt.Fprintf(stdout, "Discarding rollback pin: generation %d, manifest %.12s\n", pin.Generation, pin.ManifestHash)
	} else {
		fmt.Fprintln(stdout, "No rollback pin was set (nothing to accept).")
	}
	if err := sess.St.ClearPin(); err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	if err := sess.LoadRemote(); err != nil {
		return cliFailLogged(stderr, sess, fmt.Errorf("pin cleared, but re-validating the remote failed: %w", err))
	}
	if sess.RS.Manifest == nil {
		fmt.Fprintln(stdout, "Accepted: remote is currently empty; next push recreates it.")
		return 0
	}
	if err := sess.Eng.CommitPin(sess.RS); err != nil {
		return cliFailLogged(stderr, sess, fmt.Errorf("pin cleared, but re-pinning the current state failed: %w", err))
	}
	fmt.Fprintf(stdout, "Accepted: now pinned at generation %d.\n", sess.RS.Manifest.Generation)
	return 0
}

// cmdAcceptRepoChange is the explicit, user-presence-gated override for a
// repository-identity mismatch: it clears the local repo-id pin so the next
// fetch re-establishes trust-on-first-use. Use only after deliberately
// re-pointing a remote at a different repository.
func cmdAcceptRepoChange(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("accept-repo-change", flag.ContinueOnError)
	fs.SetOutput(stderr)
	remote := fs.String("remote", "origin", "cloak remote to accept the repo-identity change for")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := userpresence.Require("accept repo-identity change on remote "+*remote, stderr); err != nil {
		return cliFail(stderr, err)
	}
	sess, err := setup.OpenLocal(*remote, "", stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()

	if rid, ok, _ := sess.St.LoadRepoID(); ok {
		fmt.Fprintf(stdout, "Discarding pinned repo id: %s\n", rid)
	} else {
		fmt.Fprintln(stdout, "No repo id was pinned (nothing to accept).")
	}
	if err := sess.St.ClearRepoID(); err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	if err := sess.LoadRemote(); err != nil {
		return cliFailLogged(stderr, sess, fmt.Errorf("repo-id pin cleared, but re-validating the remote failed: %w", err))
	}
	if sess.RS.Manifest == nil {
		fmt.Fprintln(stdout, "Accepted: remote is currently empty; next push recreates it.")
		return 0
	}
	if err := sess.Eng.CommitPin(sess.RS); err != nil {
		return cliFailLogged(stderr, sess, fmt.Errorf("repo-id pin cleared, but re-pinning failed: %w", err))
	}
	fmt.Fprintf(stdout, "Accepted: now pinned to repo id %s (generation %d).\n",
		sess.RS.Manifest.RepoID, sess.RS.Manifest.Generation)
	return 0
}
