// Unit tests for blob-read failure classification: transport failures
// (network/auth) must surface as themselves, never as TAMPER alarms; only
// unclassifiable failures mean manifest-promised content is unreadable.
package backend

import (
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

func TestClassifyBlobRead(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		want   cloakerr.Kind
	}{
		{"dns failure", "ssh: Could not resolve host: example.invalid", cloakerr.Network},
		{"connection refused", "fatal: unable to connect: Connection refused", cloakerr.Network},
		{"auth failure", "git@github.com: Permission denied (publickey).", cloakerr.Auth},
		{"missing blob", "fatal: bad object deadbeef", cloakerr.Tamper},
		{"empty stderr", "", cloakerr.Tamper},
		// A withholding host cannot escape Tamper by injecting a benign
		// transport pattern into server "remote:" sideband (CR-001): the
		// sideband is stripped before classification, leaving only the
		// client-origin missing-object failure.
		{"host sideband cannot mask withhold", "remote: connection reset by the host\nfatal: bad object deadbeef", cloakerr.Tamper},
		// A genuine client-origin connection error (no "remote:" prefix) is
		// still classified as the transport failure it is, not Tamper.
		{"client connection error stays network", "fatal: unable to access: Connection refused", cloakerr.Network},
	}
	for _, c := range cases {
		err := classifyBlobRead("packs/x.age", &gitx.GitError{
			Args: []string{"cat-file"}, ExitCode: 128, Stderr: c.stderr,
		})
		if kind, ok := cloakerr.KindOf(err); !ok || kind != c.want {
			t.Errorf("%s: classified %v, want %v (err: %v)", c.name, kind, c.want, err)
		}
	}
}

func TestCappingWriter(t *testing.T) {
	// Under the limit: every byte passes through, no overflow.
	var under strings.Builder
	cw := &cappingWriter{w: &under, limit: 10}
	if n, err := cw.Write([]byte("hello")); n != 5 || err != nil {
		t.Fatalf("under-limit write: n=%d err=%v", n, err)
	}
	if cw.overflow || under.String() != "hello" {
		t.Fatalf("under-limit: overflow=%v buf=%q", cw.overflow, under.String())
	}

	// A write that crosses the limit forwards up to the cap, discards the
	// rest, reports a full write, and flags overflow.
	var over strings.Builder
	cw = &cappingWriter{w: &over, limit: 4}
	if n, err := cw.Write([]byte("abcdef")); n != 6 || err != nil {
		t.Fatalf("overflow write: n=%d err=%v", n, err)
	}
	// Subsequent bytes are fully discarded but still acknowledged.
	if n, err := cw.Write([]byte("ghi")); n != 3 || err != nil {
		t.Fatalf("post-overflow write: n=%d err=%v", n, err)
	}
	if !cw.overflow || over.String() != "abcd" || cw.n != 4 {
		t.Fatalf("overflow: overflow=%v buf=%q n=%d", cw.overflow, over.String(), cw.n)
	}
}
