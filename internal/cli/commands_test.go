// Unit tests for the operator commands that need no remote: version, the
// keygen/export/import lifecycle on the file backend, usage errors, and
// the debug encrypt/decrypt round trip. Tests that would hit the
// user-presence gate skip when stdin is a real terminal so they can never
// fire an authentication prompt from an interactive `go test`.
package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/term"
)

func skipIfInteractive(t *testing.T) {
	t.Helper()
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal; skipping to avoid a user-presence prompt")
	}
}

func run(t *testing.T, args []string, stdin string) (code int, out, errb bytes.Buffer) {
	t.Helper()
	code = Main(args, strings.NewReader(stdin), &out, &errb)
	return code, out, errb
}

func TestVersionCommand(t *testing.T) {
	code, out, _ := run(t, []string{"version"}, "")
	if code != 0 || !strings.Contains(out.String(), "git-cloak") {
		t.Fatalf("version: code=%d out=%q", code, out.String())
	}
}

func TestKeyLifecycle(t *testing.T) {
	skipIfInteractive(t)
	dir := t.TempDir()
	ref := "file:" + filepath.Join(dir, "key")

	code, out, errb := run(t, []string{"keygen", "--key", ref}, "")
	if code != 0 {
		t.Fatalf("keygen: code=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "Generated master key") {
		t.Fatalf("keygen output = %q", out.String())
	}

	if code, _, _ = run(t, []string{"keygen", "--key", ref}, ""); code == 0 {
		t.Fatal("second keygen over an existing key succeeded")
	}

	// Non-interactive (piped) stdin must refuse export without the explicit
	// opt-in, so a backgrounded caller cannot silently dump key bytes.
	if code, _, _ = run(t, []string{"key", "export", "--key", ref}, ""); code == 0 {
		t.Fatal("key export to a non-interactive stdin succeeded without --force-insecure")
	}

	code, out, errb = run(t, []string{"key", "export", "--key", ref, "--force-insecure"}, "")
	if code != 0 {
		t.Fatalf("key export: code=%d stderr=%q", code, errb.String())
	}
	exported := strings.TrimSpace(out.String())
	if !strings.HasPrefix(exported, "cloak-key-v0:") {
		t.Fatalf("export encoding = %q", exported)
	}

	ref2 := "file:" + filepath.Join(dir, "key2")
	if code, _, errb = run(t, []string{"key", "import", "--key", ref2}, exported+"\n"); code != 0 {
		t.Fatalf("key import: code=%d stderr=%q", code, errb.String())
	}
	code, out, _ = run(t, []string{"key", "export", "--key", ref2, "--force-insecure"}, "")
	if code != 0 || strings.TrimSpace(out.String()) != exported {
		t.Fatal("imported key does not round-trip to the same export")
	}
}

func TestKeyImportRejectsGarbage(t *testing.T) {
	skipIfInteractive(t)
	ref := "file:" + filepath.Join(t.TempDir(), "key")
	if code, _, _ := run(t, []string{"key", "import", "--key", ref}, "not-a-key\n"); code == 0 {
		t.Fatal("import accepted garbage")
	}
	if code, _, _ := run(t, []string{"key", "import", "--key", ref}, ""); code == 0 {
		t.Fatal("import accepted empty stdin")
	}
}

// failingReader returns a non-EOF error on Read, so bufio.Scanner.Scan()
// stops with sc.Err() != nil - the broken-stdin path key import must surface
// rather than misreport as "no key on stdin".
type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestKeyImportSurfacesStdinReadError(t *testing.T) {
	ref := "file:" + filepath.Join(t.TempDir(), "key")
	sentinel := errors.New("stdin pipe broke")
	var out, errb bytes.Buffer
	code := cmdKeyImport([]string{"--key", ref}, failingReader{sentinel}, &out, &errb)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if strings.Contains(errb.String(), "no key on stdin") {
		t.Fatalf("read error misreported as empty stdin: %q", errb.String())
	}
	if !strings.Contains(errb.String(), "read key from stdin") || !strings.Contains(errb.String(), sentinel.Error()) {
		t.Fatalf("stderr does not surface the read error: %q", errb.String())
	}
	if _, err := os.Stat(ref[len("file:"):]); err == nil {
		t.Fatal("a key file was written despite the stdin read failure")
	}
}

func TestKeygenExistingKeyGuidance(t *testing.T) {
	skipIfInteractive(t)
	ref := "file:" + filepath.Join(t.TempDir(), "key")
	if code, _, errb := run(t, []string{"keygen", "--key", ref}, ""); code != 0 {
		t.Fatalf("keygen: %s", errb.String())
	}
	code, _, errb := run(t, []string{"keygen", "--key", ref}, "")
	if code == 0 {
		t.Fatal("second keygen over an existing key succeeded")
	}
	if !strings.Contains(errb.String(), "key delete --key "+ref) {
		t.Fatalf("keygen-exists guidance missing the delete command; stderr=%q", errb.String())
	}
}

func TestKeyDeleteConfirmation(t *testing.T) {
	skipIfInteractive(t)
	dir := t.TempDir()
	ref := "file:" + filepath.Join(dir, "key")
	path := filepath.Join(dir, "key")
	if code, _, errb := run(t, []string{"keygen", "--key", ref}, ""); code != 0 {
		t.Fatalf("keygen: %s", errb.String())
	}

	// A non-YES answer aborts and leaves the key in place.
	code, _, errb := run(t, []string{"key", "delete", "--key", ref}, "no\n")
	if code == 0 {
		t.Fatal("delete proceeded without a YES confirmation")
	}
	if !strings.Contains(errb.String(), "aborted") {
		t.Fatalf("expected an abort message, got %q", errb.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key removed despite a non-YES answer: %v", err)
	}

	// Lowercase "yes" must not count: caps are enforced.
	if code, _, _ := run(t, []string{"key", "delete", "--key", ref}, "yes\n"); code == 0 {
		t.Fatal("lowercase 'yes' was accepted; caps must be enforced")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key removed on lowercase yes: %v", err)
	}

	// Exact "YES" deletes the key.
	if code, _, errb := run(t, []string{"key", "delete", "--key", ref}, "YES\n"); code != 0 {
		t.Fatalf("delete with YES: code=%d stderr=%q", code, errb.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("key still present after YES delete: err=%v", err)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"key"}, {"key", "frobnicate"}, {"debug"}, {"debug", "frobnicate"}} {
		if code, _, _ := run(t, args, ""); code != 2 {
			t.Errorf("%v: exit = %d, want 2", args, code)
		}
	}
}

func TestDebugEncryptDecryptRoundTrip(t *testing.T) {
	skipIfInteractive(t)
	ref := "file:" + filepath.Join(t.TempDir(), "key")
	if code, _, errb := run(t, []string{"keygen", "--key", ref}, ""); code != 0 {
		t.Fatalf("keygen: %s", errb.String())
	}

	plaintext := "attack at dawn\n"
	var ct, errb bytes.Buffer
	if code := Main([]string{"debug", "encrypt", "--key", ref}, strings.NewReader(plaintext), &ct, &errb); code != 0 {
		t.Fatalf("debug encrypt: code=%d stderr=%q", code, errb.String())
	}
	if strings.Contains(ct.String(), "attack at dawn") {
		t.Fatal("ciphertext contains the plaintext")
	}
	var pt bytes.Buffer
	if code := Main([]string{"debug", "decrypt", "--key", ref}, bytes.NewReader(ct.Bytes()), &pt, &errb); code != 0 {
		t.Fatalf("debug decrypt: code=%d stderr=%q", code, errb.String())
	}
	if pt.String() != plaintext {
		t.Fatalf("round trip = %q, want %q", pt.String(), plaintext)
	}
}

func TestDebugDecryptWrongKeyFails(t *testing.T) {
	skipIfInteractive(t)
	dir := t.TempDir()
	ref1 := "file:" + filepath.Join(dir, "k1")
	ref2 := "file:" + filepath.Join(dir, "k2")
	for _, ref := range []string{ref1, ref2} {
		if code, _, errb := run(t, []string{"keygen", "--key", ref}, ""); code != 0 {
			t.Fatalf("keygen: %s", errb.String())
		}
	}
	var ct, errb bytes.Buffer
	if code := Main([]string{"debug", "encrypt", "--key", ref1}, strings.NewReader("secret"), &ct, &errb); code != 0 {
		t.Fatal("encrypt failed")
	}
	var pt bytes.Buffer
	if code := Main([]string{"debug", "decrypt", "--key", ref2}, bytes.NewReader(ct.Bytes()), &pt, &errb); code == 0 {
		t.Fatal("decrypt under the wrong key succeeded")
	}
	if !strings.Contains(errb.String(), "TAMPER ALARM") {
		t.Fatalf("wrong-key decrypt stderr = %q, want TAMPER ALARM wording", errb.String())
	}
}
