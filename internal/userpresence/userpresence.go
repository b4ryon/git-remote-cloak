// Package userpresence gates sensitive cloak operations (keygen, key
// export, rekey, accept-rollback) behind a device-owner check: Touch ID
// with password fallback on macOS. The remote-helper sync path never calls
// this, so unattended sync never prompts. Non-interactive invocations
// (launchd, scripts, tests) skip the check with a notice: this gate guards
// against interactive misuse; the keychain item ACL, not this prompt, is
// the boundary against same-user code.
package userpresence

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// IsInteractive reports whether stdin is an interactive terminal. The test
// must be a real isatty check: /dev/null is a character device, so a mode
// check would misclassify headless subprocess invocations as interactive.
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// Require runs the platform user-presence check for an interactive
// session; non-interactive sessions pass with a notice on stderr. The
// terminal test must be a real isatty check: /dev/null is a character
// device, so a mode check would misclassify headless subprocess
// invocations as interactive and fire authentication prompts from
// background jobs.
func Require(reason string, stderr io.Writer) error {
	if !IsInteractive() {
		fmt.Fprintf(stderr, "cloak: note: user-presence check for %s skipped (non-interactive session)\n", reason)
		return nil
	}
	return require(reason)
}
