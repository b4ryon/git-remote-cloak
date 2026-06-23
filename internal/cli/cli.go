// Package cli implements the git-cloak operator command line: key
// management, status, repack/rekey, accept-rollback, and hidden debug
// subcommands used by the test harness and milestone gates. M0 scaffold:
// usage and dispatch shell only; commands land milestone by milestone.
package cli

import (
	"fmt"
	"io"

	"github.com/b4ryon/git-remote-cloak/internal/version"
)

const usage = `git-cloak: operator tool for git-remote-cloak encrypted remotes

Usage:
  git cloak <command> [options]

Commands:
  version           print the build version
  keygen            generate the shared master key
  key export        print the key for transfer/backup (user-presence gated)
  key import        import a key on a second machine
  key delete        delete a stored key (asks for a YES confirmation)
  status            show remote generation, packs, applied state
  repack            full consolidation of the remote into one pack
  rekey             full repack under a new master key (user-presence gated)
  accept-rollback   accept a remote generation regression once (user-presence gated)
  accept-repo-change accept a remote repo-identity change once (user-presence gated)
`

// Main runs the operator CLI and returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "git-cloak %s\n", version.String())
		return 0
	case "keygen":
		return cmdKeygen(args[1:], stdout, stderr)
	case "repack":
		return cmdRepack(args[1:], stdout, stderr)
	case "rekey":
		return cmdRekey(args[1:], stdout, stderr)
	case "status":
		return cmdStatus(args[1:], stdout, stderr)
	case "accept-rollback":
		return cmdAcceptRollback(args[1:], stdout, stderr)
	case "accept-repo-change":
		return cmdAcceptRepoChange(args[1:], stdout, stderr)
	case "key":
		return dispatchKey(args, stdin, stdout, stderr)
	case "debug":
		return dispatchDebug(args, stdin, stdout, stderr)
	}
	fmt.Fprintf(stderr, "cloak: unknown or not yet implemented command %q (see git-cloak --help)\n", args[0])
	return 2
}
