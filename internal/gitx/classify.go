// Transport error classification: maps git stderr patterns to the cloak
// error taxonomy so auth, network, and missing-repository failures are
// reported as what they are (fixing gcrypt's everything-is-"repository not
// found"). The table is pinned by golden-stderr unit tests; new git
// versions should only ever require table edits.
package gitx

import (
	"errors"
	"regexp"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

var classifyTable = []struct {
	kind cloakerr.Kind
	re   *regexp.Regexp
}{
	{cloakerr.Auth, regexp.MustCompile(`(?i)permission denied \(publickey`)},
	{cloakerr.Auth, regexp.MustCompile(`(?i)could not read (username|password)`)},
	{cloakerr.Auth, regexp.MustCompile(`(?i)authentication failed`)},
	{cloakerr.Auth, regexp.MustCompile(`(?i)invalid username or (password|token)`)},
	{cloakerr.Auth, regexp.MustCompile(`(?i)host key verification failed`)},
	{cloakerr.Network, regexp.MustCompile(`(?i)could not resolve host`)},
	{cloakerr.Network, regexp.MustCompile(`(?i)connection (refused|reset|timed out)`)},
	{cloakerr.Network, regexp.MustCompile(`(?i)network is unreachable`)},
	{cloakerr.Network, regexp.MustCompile(`(?i)operation timed out`)},
	{cloakerr.Network, regexp.MustCompile(`(?i)early eof`)},
	{cloakerr.RepoNotFound, regexp.MustCompile(`(?i)repository .*not found`)},
	{cloakerr.RepoNotFound, regexp.MustCompile(`(?i)does not appear to be a git repository`)},
	{cloakerr.RepoNotFound, regexp.MustCompile(`(?i)fatal: '[^']*' does not exist`)},
}

// StripServerSideband removes server-relayed sideband lines (those git prints
// with a "remote:" prefix) from captured stderr. That text is controlled by
// the untrusted host, so on integrity-sensitive paths it must not drive
// transport classification: otherwise a host could inject a benign-looking
// pattern (e.g. "connection reset") to downgrade a genuine missing-content
// failure out of the Tamper class. Client-origin transport diagnostics
// (DNS/connection/auth failures) are not "remote:"-prefixed and are kept.
func StripServerSideband(stderr string) string {
	lines := strings.Split(stderr, "\n")
	kept := lines[:0]
	for _, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "remote:") {
			continue
		}
		kept = append(kept, ln)
	}
	return strings.Join(kept, "\n")
}

// ClassifyTransport wraps a git transport failure with its taxonomy kind;
// unmatched failures stay LocalGit with the full stderr preserved, never
// guessed into a more specific class. A timeout or cancel maps to Network
// (a stalled host), so it is never escalated as tamper. The table below
// matches host-influenced stderr; the fail-safe default for an unrecognized
// failure is the conservative LocalGit (and Tamper for blob reads), so a
// host cannot downgrade a withhold into a benign class.
func ClassifyTransport(op string, err error) error {
	// A killed (timeout) or aborted (cancel) git subprocess is a stalled or
	// interrupted transport, never tamper, so both map to the same Network kind.
	var te *TimeoutError
	var ce *CanceledError
	if errors.As(err, &te) || errors.As(err, &ce) {
		return cloakerr.New(cloakerr.Network, op, err)
	}
	var ge *GitError
	if errors.As(err, &ge) {
		for _, c := range classifyTable {
			if c.re.MatchString(ge.Stderr) {
				return cloakerr.New(c.kind, op, err)
			}
		}
	}
	return cloakerr.New(cloakerr.LocalGit, op, err)
}
