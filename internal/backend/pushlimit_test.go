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

func TestBackendRefRejectedPorcelainFlag(t *testing.T) {
	// git --porcelain renders a refused ref update with a leading "!" flag and a
	// "<from>:<to>" spec on stdout -- a genuine LOCAL compare-and-swap signal,
	// whatever reason the host relays. Both a server-side mid-connection
	// rejection and git's own stale-advertisement check produce it.
	for name, stdout := range map[string]string{
		"server-side": "To origin\n" +
			"!\t9e90bca:refs/heads/cloak\t[remote rejected] (failed to update ref)\nDone",
		"client-side": "To origin\n" +
			"!\t9e90bca:refs/heads/cloak\t[rejected] (stale info)\nDone",
		// The reason text is git-version/host dependent; detection must not
		// depend on it (this reason matches none of the old marker phrases --
		// exactly the case that regressed the marker scan in CI).
		"reason-independent": "To origin\n" +
			"!\t9e90bca:refs/heads/cloak\t[remote rejected] (cannot update the ref right now)\nDone",
	} {
		if !backendRefRejected(stdout, "cloak") {
			t.Fatalf("%s: porcelain '!' rejection for our branch not detected", name)
		}
	}
}

func TestBackendRefRejectedIgnoresSideband(t *testing.T) {
	// A hostile host cannot forge a rejection: CAS phrases in its "remote:"
	// sideband never begin with "!\t", and stderr is not scanned at all. With no
	// genuine porcelain "!" line for our branch this is not a CAS loss, so the
	// push surfaces the real (transport) failure instead of retrying to
	// exhaustion. Stdout here is deliberately adversarial (host text never
	// reaches stdout in practice) to show the flag itself cannot be spoofed.
	stdout := "remote: !\t<oid>:refs/heads/cloak\t[rejected] (non-fast-forward)\n" +
		"remote: cannot lock ref, stale info, fetch first - just kidding\n" +
		"To origin\nDone"
	if backendRefRejected(stdout, "cloak") {
		t.Fatal("host-forged sideband rejection must not count as a CAS loss")
	}
}

func TestBackendRefRejectedOtherBranch(t *testing.T) {
	// A rejection for an unrelated ref must not be read as our branch's CAS loss.
	stdout := "To origin\n" +
		"!\t<oid>:refs/heads/not-cloak\t[rejected] (non-fast-forward)\nDone"
	if backendRefRejected(stdout, "cloak") {
		t.Fatal("unrelated ref rejection misattributed to our branch")
	}
}
