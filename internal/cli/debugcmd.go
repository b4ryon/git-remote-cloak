// git-cloak hidden debug subcommands used by milestone gates and the test
// harness: stream encryption/decryption with the cloak stanza. Not listed
// in the user-facing usage text.
package cli

import (
	"fmt"
	"io"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// dispatchDebug routes `git cloak debug <sub>` to the matching hidden debug
// command. args is the full argv with args[0] == "debug"; an unknown or
// missing subcommand prints the usage line and returns code 2.
func dispatchDebug(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) >= 2 {
		switch args[1] {
		case "encrypt":
			return cmdDebugEncrypt(args[2:], stdin, stdout, stderr)
		case "decrypt":
			return cmdDebugDecrypt(args[2:], stdin, stdout, stderr)
		case "seed-remote":
			return cmdDebugSeedRemote(args[2:], stdout, stderr)
		}
	}
	fmt.Fprintln(stderr, "cloak: usage: git cloak debug encrypt|decrypt|seed-remote [--key <ref>]")
	return 2
}

// loadKeyOnly parses a flagset named name that accepts only the standard
// --key flag, then loads the referenced master key. A parse error returns
// code 2; a load error is printed and returns code 1. When ok is true the
// caller owns the returned Key and must defer k.Wipe().
func loadKeyOnly(name string, args []string, stderr io.Writer) (k keystore.Key, code int, ok bool) {
	fs := newFlagSet(name, stderr)
	ref := keyFlag(fs)
	if err := fs.Parse(args); err != nil {
		return keystore.Key{}, 2, false
	}
	k, err := keystore.Load(*ref)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return keystore.Key{}, 1, false
	}
	return k, 0, true
}

func cmdDebugEncrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	k, code, ok := loadKeyOnly("debug encrypt", args, stderr)
	if !ok {
		return code
	}
	defer k.Wipe()
	w, err := agecrypt.Encrypt(stdout, k)
	if err != nil {
		return printFail(stderr, err)
	}
	// io.Copy and Close surface raw OS errors (no 'cloak:' prefix); wrap both
	// with the encrypt context one idiom rather than two identical blocks.
	encryptFail := func(err error) int {
		fmt.Fprintf(stderr, "cloak: encrypt: %v\n", err)
		return 1
	}
	if _, err := io.Copy(w, stdin); err != nil {
		return encryptFail(err)
	}
	if err := w.Close(); err != nil {
		return encryptFail(err)
	}
	return 0
}

func cmdDebugDecrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	k, code, ok := loadKeyOnly("debug decrypt", args, stderr)
	if !ok {
		return code
	}
	defer k.Wipe()
	r, err := agecrypt.Decrypt(stdin, k)
	if err != nil {
		return printFail(stderr, err)
	}
	if _, err := io.Copy(stdout, r); err != nil {
		return printFail(stderr, err)
	}
	return 0
}
