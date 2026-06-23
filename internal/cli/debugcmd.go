// git-cloak hidden debug subcommands used by milestone gates and the test
// harness: stream encryption/decryption with the cloak stanza. Not listed
// in the user-facing usage text.
package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

func cmdDebugEncrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("debug encrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ref := fs.String("key", keystore.DefaultRef(), "key reference (file:<path>)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	k, err := keystore.Load(*ref)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer k.Wipe()
	w, err := agecrypt.Encrypt(stdout, k)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := io.Copy(w, stdin); err != nil {
		fmt.Fprintf(stderr, "cloak: encrypt: %v\n", err)
		return 1
	}
	if err := w.Close(); err != nil {
		fmt.Fprintf(stderr, "cloak: encrypt: %v\n", err)
		return 1
	}
	return 0
}

func cmdDebugDecrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("debug decrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ref := fs.String("key", keystore.DefaultRef(), "key reference (file:<path>)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	k, err := keystore.Load(*ref)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer k.Wipe()
	r, err := agecrypt.Decrypt(stdin, k)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := io.Copy(stdout, r); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
