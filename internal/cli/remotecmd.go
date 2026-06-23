// git-cloak remote-operating commands: repack (full consolidation +
// squash) and rekey (full repack under a new master key). Both take the
// same per-remote lock as the helper, so they serialize with running syncs.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/setup"
	"github.com/b4ryon/git-remote-cloak/internal/userpresence"
)

func cliFail(stderr io.Writer, err error) int {
	msg := err.Error()
	if !strings.HasPrefix(msg, "cloak:") {
		msg = "cloak: " + msg
	}
	fmt.Fprintln(stderr, msg)
	return 1
}

// cliFailLogged reports err and, when a session is open, points the operator
// at that remote's debug log for self-service troubleshooting (F5).
func cliFailLogged(stderr io.Writer, sess *setup.Session, err error) int {
	code := cliFail(stderr, err)
	if sess != nil && sess.St != nil {
		fmt.Fprintln(stderr, "see the debug log for details: "+sess.St.LogPath())
	}
	return code
}

func cmdRepack(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("repack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	remote := fs.String("remote", "origin", "cloak remote to repack")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sess, err := setup.Open(*remote, "", stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()
	rs, err := sess.Eng.FullRepack(sess.RS, nil)
	if err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	if len(rs.Manifest.Packs) == 0 {
		return cliFailLogged(stderr, sess, fmt.Errorf("repack produced a manifest with no packs (internal error)"))
	}
	fmt.Fprintf(stdout, "Repacked remote %q: generation %d, single pack of %d bytes (%d refs)\n",
		*remote, rs.Manifest.Generation, rs.Manifest.Packs[0].Size, len(rs.Manifest.Refs))
	return 0
}

func cmdRekey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rekey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	remote := fs.String("remote", "origin", "cloak remote to rekey")
	newRef := fs.String("new-key", "", "key reference holding the NEW master key (required; create with keygen)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *newRef == "" {
		fmt.Fprintln(stderr, "cloak: rekey requires --new-key <ref> (generate one first: git cloak keygen --key <ref>)")
		return 2
	}
	if err := userpresence.Require("rekey the remote", stderr); err != nil {
		return cliFail(stderr, err)
	}
	newKey, err := keystore.Load(*newRef)
	if err != nil {
		return cliFail(stderr, err)
	}
	defer newKey.Wipe()
	sess, err := setup.Open(*remote, "", stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()
	if newKey.ID() == sess.Eng.Key.ID() {
		fmt.Fprintln(stderr, "cloak: --new-key holds the same key the remote already uses")
		return 2
	}
	rs, err := sess.Eng.FullRepack(sess.RS, &newKey)
	if err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	if _, _, err := sess.G.Run(gitx.Opts{GitDir: sess.Eng.LocalGitDir},
		"config", "cloak.keyRef", *newRef); err != nil {
		return cliFailLogged(stderr, sess, fmt.Errorf("remote rekeyed under key %s but updating this repo's cloak.keyRef failed: %w\n  fix it manually:  git config cloak.keyRef %s",
			newKey.ID(), err, *newRef))
	}
	if len(rs.Manifest.Packs) == 0 {
		return cliFailLogged(stderr, sess, fmt.Errorf("rekey produced a manifest with no packs (internal error)"))
	}
	fmt.Fprintf(stdout, "Rekeyed remote %q under key %s: generation %d, single pack of %d bytes\n",
		*remote, newKey.ID(), rs.Manifest.Generation, rs.Manifest.Packs[0].Size)
	fmt.Fprintln(stdout, "This repo's cloak.keyRef now points at the new key.")
	fmt.Fprintln(stdout, "OTHER MACHINES: import the new key (git cloak key import) and update cloak.keyRef; the old key no longer decrypts the remote.")
	fmt.Fprintln(stdout, "NOTE: rekey does NOT protect history the host already stored under the OLD key; a leaked old key still decrypts everything pushed before this rekey. It limits exposure of FUTURE writes only. Rotate any secrets that ever appeared in history if this was a compromise response.")
	return 0
}
