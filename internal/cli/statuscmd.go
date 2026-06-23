// git-cloak status and accept-rollback: operator visibility into the
// remote (generation, packs, applied state, rollback pin) and the
// explicit, one-shot acceptance of a remote generation regression.
package cli

import (
	"fmt"
	"io"

	"github.com/b4ryon/git-remote-cloak/internal/manifest"
	"github.com/b4ryon/git-remote-cloak/internal/setup"
	"github.com/b4ryon/git-remote-cloak/internal/state"
	"github.com/b4ryon/git-remote-cloak/internal/userpresence"
)

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("status", stderr)
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
	return printManifestStatus(sess, stdout, stderr)
}

// printManifestStatus renders the populated-remote status block: pack-size
// totals, applied-pack count, local verification/identity records, and the
// sync verdict. It returns an exit code so the AppliedSet read error can route
// through cliFailLogged exactly as the inline body did.
func printManifestStatus(sess *setup.Session, stdout, stderr io.Writer) int {
	m := sess.RS.Manifest
	total, largest, smallest := packSizeStats(m.Packs)
	applied, err := sess.St.AppliedSet()
	if err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	appliedLive := countAppliedLive(m.Packs, applied)

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
	printSyncState(stdout, m, pin, pinned)
	return 0
}

// packSizeStats returns the total, largest, and smallest ciphertext size over
// the live packs. smallest stays -1 for an empty pack list, matching the
// sentinel the "smallest %d" status line prints.
func packSizeStats(packs []manifest.Pack) (total, largest, smallest int64) {
	smallest = -1
	for _, p := range packs {
		total += p.Size
		if p.Size > largest {
			largest = p.Size
		}
		if smallest < 0 || p.Size < smallest {
			smallest = p.Size
		}
	}
	return total, largest, smallest
}

// countAppliedLive counts how many live packs have already been indexed
// (applied) on this machine.
func countAppliedLive(packs []manifest.Pack, applied map[string]bool) int {
	n := 0
	for _, p := range packs {
		if applied[p.ID] {
			n++
		}
	}
	return n
}

// printSyncState prints the one-line sync verdict comparing the remote
// generation against this machine's last-verified pin.
func printSyncState(stdout io.Writer, m *manifest.Manifest, pin state.Pin, pinned bool) {
	switch {
	case pinned && m.Generation > pin.Generation:
		fmt.Fprintln(stdout, "Sync:       remote is ahead of this machine; run `git pull` to catch up")
	case pinned:
		fmt.Fprintln(stdout, "Sync:       up to date with the remote")
	default:
		fmt.Fprintln(stdout, "Sync:       first contact (run `git pull` to fetch and pin the remote)")
	}
}

// acceptSpec captures the parts that differ between the two user-presence-gated
// "accept" overrides; runAccept holds their common spine: clear a local pin,
// re-validate the remote, then re-pin the current state. The ordering is
// security-relevant (clear before any validation runs) and lives in one place.
type acceptSpec struct {
	name        string // flagset name
	remoteUsage string // -remote flag help text
	presence    string // userpresence action, e.g. "accept rollback"
	noun        string // local record being cleared, e.g. "pin" / "repo-id pin"
	repinFail   string // re-pin error tail, e.g. "re-pinning failed"
	// describe reports what is being discarded (or that nothing was set).
	describe func(sess *setup.Session)
	// clear removes the local pin.
	clear func(sess *setup.Session) error
	// accepted reports the final pinned state.
	accepted func(sess *setup.Session)
}

func runAccept(spec acceptSpec, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet(spec.name, stderr)
	remote := fs.String("remote", "origin", spec.remoteUsage)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := userpresence.Require(spec.presence+" on remote "+*remote, stderr); err != nil {
		return cliFail(stderr, err)
	}
	sess, err := setup.OpenLocal(*remote, "", stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()

	spec.describe(sess)
	if err := spec.clear(sess); err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	if err := sess.LoadRemote(); err != nil {
		return cliFailLogged(stderr, sess, fmt.Errorf("%s cleared, but re-validating the remote failed: %w", spec.noun, err))
	}
	if sess.RS.Manifest == nil {
		fmt.Fprintln(stdout, "Accepted: remote is currently empty; next push recreates it.")
		return 0
	}
	if err := sess.Eng.CommitPin(sess.RS); err != nil {
		return cliFailLogged(stderr, sess, fmt.Errorf("%s cleared, but %s: %w", spec.noun, spec.repinFail, err))
	}
	spec.accepted(sess)
	return 0
}

func cmdAcceptRollback(args []string, stdout, stderr io.Writer) int {
	return runAccept(acceptSpec{
		name:        "accept-rollback",
		remoteUsage: "cloak remote to accept the regression for",
		presence:    "accept rollback",
		noun:        "pin",
		repinFail:   "re-pinning the current state failed",
		describe: func(sess *setup.Session) {
			if pin, ok, _ := sess.St.LoadPin(); ok {
				fmt.Fprintf(stdout, "Discarding rollback pin: generation %d, manifest %.12s\n", pin.Generation, pin.ManifestHash)
			} else {
				fmt.Fprintln(stdout, "No rollback pin was set (nothing to accept).")
			}
		},
		clear: func(sess *setup.Session) error { return sess.St.ClearPin() },
		accepted: func(sess *setup.Session) {
			fmt.Fprintf(stdout, "Accepted: now pinned at generation %d.\n", sess.RS.Manifest.Generation)
		},
	}, args, stdout, stderr)
}

// cmdAcceptRepoChange is the explicit, user-presence-gated override for a
// repository-identity mismatch: it clears the local repo-id pin so the next
// fetch re-establishes trust-on-first-use. Use only after deliberately
// re-pointing a remote at a different repository.
func cmdAcceptRepoChange(args []string, stdout, stderr io.Writer) int {
	return runAccept(acceptSpec{
		name:        "accept-repo-change",
		remoteUsage: "cloak remote to accept the repo-identity change for",
		presence:    "accept repo-identity change",
		noun:        "repo-id pin",
		repinFail:   "re-pinning failed",
		describe: func(sess *setup.Session) {
			if rid, ok, _ := sess.St.LoadRepoID(); ok {
				fmt.Fprintf(stdout, "Discarding pinned repo id: %s\n", rid)
			} else {
				fmt.Fprintln(stdout, "No repo id was pinned (nothing to accept).")
			}
		},
		clear: func(sess *setup.Session) error { return sess.St.ClearRepoID() },
		accepted: func(sess *setup.Session) {
			fmt.Fprintf(stdout, "Accepted: now pinned to repo id %s (generation %d).\n",
				sess.RS.Manifest.RepoID, sess.RS.Manifest.Generation)
		},
	}, args, stdout, stderr)
}
