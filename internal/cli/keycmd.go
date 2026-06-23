// git-cloak key management commands: keygen, key export, key import. The
// user-presence (Touch ID) gate on export lands with the darwin Keychain
// backend in M5; the M1 file backend is gated only by file permissions.
package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/userpresence"
)

// keyExistsGuidance explains, with a warning, how to remove an existing key
// before a new one can be generated in its place.
func keyExistsGuidance(stderr io.Writer, ref string) {
	fmt.Fprintf(stderr, "cloak: a master key already exists at %s\n", ref)
	fmt.Fprintln(stderr, "WARNING: removing it is permanent. You will NOT be able to decrypt anything")
	fmt.Fprintln(stderr, "already pushed under it, and the key cannot be recovered unless you saved an")
	fmt.Fprintln(stderr, "export backup. Remove it first with:")
	fmt.Fprintf(stderr, "    git cloak key delete --key %s\n", ref)
	fmt.Fprintln(stderr, "(If the remote already holds data, use `git cloak rekey` to re-encrypt under a")
	fmt.Fprintln(stderr, "new key instead of deleting.)")
}

func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ref := fs.String("key", keystore.DefaultRef(), "key reference (file:<path>)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Guide the user before prompting or generating if a key is already there.
	if _, err := keystore.Load(*ref); err == nil {
		keyExistsGuidance(stderr, *ref)
		return 1
	}
	if err := userpresence.Require("generate a new master key", stderr); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	k, err := keystore.Generate()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer k.Wipe()
	if err := keystore.Save(*ref, k); err != nil {
		if errors.Is(err, keystore.ErrKeyExists) { // raced between check and save
			keyExistsGuidance(stderr, *ref)
			return 1
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "Generated master key %s\n", k.ID())
	fmt.Fprintf(stdout, "Stored at %s\n", *ref)
	fmt.Fprintf(stdout, "Back it up NOW to two independent locations: git cloak key export --key %s\n", *ref)
	return 0
}

func cmdKeyExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("key export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ref := fs.String("key", keystore.DefaultRef(), "key reference (file:<path>)")
	forceInsecure := fs.Bool("force-insecure", false,
		"allow export when stdin is not a terminal, skipping the user-presence gate (for scripted backups)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// On a non-tty stdin the user-presence gate silently passes, so a piped
	// or backgrounded caller could exfiltrate raw key bytes with no prompt.
	// Refuse unless the operator explicitly opts in. A terminal redirecting
	// only stdout (e.g. `key export > backup`) keeps stdin a tty and is fine.
	if !userpresence.IsInteractive() && !*forceInsecure {
		fmt.Fprintln(stderr, "cloak: refusing to export the master key with a non-interactive stdin (no user-presence gate possible); run from a terminal, or pass --force-insecure for a scripted backup")
		return 1
	}
	if err := userpresence.Require("export the master key", stderr); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	k, err := keystore.Load(*ref)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer k.Wipe()
	fmt.Fprintln(stdout, k.Export())
	return 0
}

func cmdKeyImport(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("key import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ref := fs.String("key", keystore.DefaultRef(), "key reference (file:<path>)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sc := bufio.NewScanner(stdin)
	if !sc.Scan() {
		fmt.Fprintln(stderr, "cloak: no key on stdin (paste the output of: git cloak key export)")
		return 1
	}
	k, err := keystore.ParseExport(sc.Text())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer k.Wipe()
	if err := keystore.Save(*ref, k); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "Imported master key %s\n", k.ID())
	fmt.Fprintf(stdout, "Stored at %s\n", *ref)
	return 0
}

func cmdKeyDelete(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("key delete", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ref := fs.String("key", keystore.DefaultRef(), "key reference (file:<path> or keychain:<name>)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintf(stderr, "WARNING: this permanently deletes the master key at %s.\n", *ref)
	fmt.Fprintln(stderr, "You will NOT be able to decrypt anything already pushed under it, and the key")
	fmt.Fprintln(stderr, "cannot be recovered unless you saved an export backup.")
	fmt.Fprint(stderr, "Type YES (in capitals) to delete, anything else to abort: ")
	sc := bufio.NewScanner(stdin)
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != "YES" {
		fmt.Fprintln(stderr, "cloak: aborted; key not deleted")
		return 1
	}
	if err := keystore.Delete(*ref); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "Deleted master key at %s\n", *ref)
	return 0
}
