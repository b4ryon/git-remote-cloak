// Command git-remote-cloak is the single binary for the cloak encrypted
// remote helper. Invoked by git as "git-remote-cloak" (for cloak:: URLs) it
// speaks the gitremote-helpers protocol on stdin/stdout; invoked as
// "git-cloak" (the symlink that backs "git cloak ...") it runs the operator
// CLI (keygen, status, repack, ...).
package main

import (
	"os"
	"path/filepath"

	"github.com/b4ryon/git-remote-cloak/internal/cli"
	"github.com/b4ryon/git-remote-cloak/internal/helper"
)

func main() {
	args := os.Args[1:]
	// The operator CLI is reached ONLY through the git-cloak symlink (git's
	// "git cloak ..." subcommand dispatch). Everything else is git driving the
	// remote helper as "git-remote-cloak <remote-name> <backend-url>". We must
	// not special-case a first argument of "cloak": git strips the cloak::
	// scheme before invoking us, so a remote literally named "cloak" arrives as
	// args[0]=="cloak", and treating that as a CLI request would misroute every
	// fetch/push through such a remote.
	if filepath.Base(os.Args[0]) == "git-cloak" {
		os.Exit(cli.Main(args, os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(helper.Main(args, os.Stdin, os.Stdout, os.Stderr))
}
