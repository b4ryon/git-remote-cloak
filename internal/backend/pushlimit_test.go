// Golden-stderr tests for classifyPushFailure: a host's own per-file size
// rejection (the Tier 1a backstop) must be reported as TooLarge, while every
// other push failure keeps falling through to the transport classifier.
package backend

import (
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

func TestClassifyPushFailureHostFileLimit(t *testing.T) {
	// A captured GitHub GH001 rejection (the host relays it under "remote:").
	stderr := "remote: error: GH001: Large files detected. You may want to try Git Large File Storage.\n" +
		"remote: error: File big.bin is 142.00 MB; this exceeds GitHub's file size limit of 100.00 MB\n" +
		"! [remote rejected] <oid> -> refs/heads/cloak (pre-receive hook declined)\n" +
		"error: failed to push some refs to 'github.com:you/repo.git'"
	ge := &gitx.GitError{Args: []string{"push"}, ExitCode: 1, Stderr: stderr}
	err := classifyPushFailure("", stderr, ge)
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.TooLarge {
		t.Fatalf("GH001 rejection not classified TooLarge: %v", err)
	}
}

func TestClassifyPushFailureFallsThrough(t *testing.T) {
	// A transport failure must NOT be misread as a size rejection.
	stderr := "fatal: unable to access 'https://x/': Could not resolve host: example.invalid"
	ge := &gitx.GitError{Args: []string{"push"}, ExitCode: 128, Stderr: stderr}
	err := classifyPushFailure("", stderr, ge)
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Network {
		t.Fatalf("transport failure should classify Network, got: %v", err)
	}
}
