// Golden-stderr tests pinning the transport error classification table.
package gitx

import (
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

func TestClassifyTransportGoldens(t *testing.T) {
	cases := []struct {
		stderr string
		want   cloakerr.Kind
	}{
		{"git@github.com: Permission denied (publickey).\nfatal: Could not read from remote repository.", cloakerr.Auth},
		{"fatal: could not read Username for 'https://github.com': terminal prompts disabled", cloakerr.Auth},
		{"fatal: Authentication failed for 'https://github.com/x/y.git/'", cloakerr.Auth},
		{"Host key verification failed.\nfatal: Could not read from remote repository.", cloakerr.Auth},
		{"ssh: Could not resolve hostname github.com: nodename nor servname provided", cloakerr.Network},
		{"ssh: connect to host github.com port 22: Connection refused", cloakerr.Network},
		{"ssh: connect to host github.com port 22: Operation timed out", cloakerr.Network},
		{"fatal: early EOF\nfatal: fetch-pack: invalid index-pack output", cloakerr.Network},
		{"ERROR: Repository not found.\nfatal: Could not read from remote repository.", cloakerr.RepoNotFound},
		{"fatal: '/tmp/nope' does not appear to be a git repository", cloakerr.RepoNotFound},
		{"fatal: some brand new git error nobody has seen", cloakerr.LocalGit},
	}
	for _, c := range cases {
		err := ClassifyTransport("op", &GitError{Args: []string{"fetch"}, ExitCode: 128, Stderr: c.stderr})
		kind, ok := cloakerr.KindOf(err)
		if !ok || kind != c.want {
			t.Errorf("stderr %q classified %v, want %v", c.stderr, kind, c.want)
		}
	}
}

func TestClassifyNonGitError(t *testing.T) {
	err := ClassifyTransport("op", errTest{})
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.LocalGit {
		t.Fatalf("non-GitError classified %v", kind)
	}
}

// A timed-out or canceled git subprocess is a stalled host, not tamper: it
// must classify as Network so the blob-read path does not escalate it to a
// false TAMPER alarm.
func TestClassifyTimeoutAndCancel(t *testing.T) {
	for _, err := range []error{
		&TimeoutError{Args: []string{"fetch"}},
		&CanceledError{Args: []string{"fetch"}},
	} {
		got := ClassifyTransport("op", err)
		if kind, ok := cloakerr.KindOf(got); !ok || kind != cloakerr.Network {
			t.Fatalf("%T classified %v, want Network", err, kind)
		}
	}
}

type errTest struct{}

func (errTest) Error() string { return "x" }
