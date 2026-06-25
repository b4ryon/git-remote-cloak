// Package backend manages the hidden bare mirror of the remote backend
// branch (.git/cloak/<remote>/backend.git): fetching the encrypted state
// from the host (partial blob:none mirror with automatic full-fetch
// fallback), reading manifest/pack blobs, building the deterministic
// chained/squash commits without a worktree, and pushing them. This is the
// ONLY package allowed to construct a backend `git push` command line; it
// exposes no code path that can emit a plain --force.
package backend

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/term"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

// filterRejectedRe matches the git stderr a host emits when it refuses the
// partial-clone filter. It is deliberately specific so an unrelated error
// merely containing the word "filter" does not silently disable the partial
// mirror.
var filterRejectedRe = regexp.MustCompile(`(?i)(filter[a-z]*\b.*(not recognized|not supported|unsupported|declined|not allowed))|((not recognized|not supported|unsupported).*filter)`)

// stdinIsTTY reports whether this process's stdin is an interactive
// terminal, used to avoid imposing a timeout that could kill a credential or
// passphrase prompt during a human-driven network operation.
func stdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// remoteHeadRef is where the fetched backend branch tip is stored locally.
const remoteHeadRef = "refs/cloak/remote-head"

// partialFilter keeps the manifest inline (small blob) while pack blobs
// above the limit transfer lazily on first read.
const partialFilter = "blob:limit=1m"

// Backend is an opened bare mirror bound to a host URL and branch.
type Backend struct {
	g       *gitx.G
	gitDir  string
	url     string
	branch  string
	log     *slog.Logger
	partial bool
}

// Open initializes (if needed) and configures the bare mirror at gitDir for
// the given host URL. The remote is configured as a blob:none promisor so
// pack blobs download lazily; if the host rejects filtering, Fetch falls
// back to full fetches and logs it.
func Open(g *gitx.G, gitDir, url, branch string, log *slog.Logger) (*Backend, error) {
	b := &Backend{g: g, gitDir: gitDir, url: url, branch: branch, log: log, partial: true}
	if _, _, err := b.g.Run(gitx.Opts{}, "init", "--bare", "--initial-branch", branch, gitDir); err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "init backend mirror", err)
	}
	// blob:limit inlines small blobs (the manifest) while large pack blobs
	// download lazily via the promisor machinery only when actually read,
	// which is what lets consolidation lineage (Replaces) skip downloads.
	cfg := [][2]string{
		{"remote.origin.url", url},
		{"remote.origin.fetch", "+refs/heads/" + branch + ":" + remoteHeadRef},
		{"remote.origin.tagopt", "--no-tags"},
		{"remote.origin.promisor", "true"},
		{"remote.origin.partialclonefilter", partialFilter},
	}
	for _, kv := range cfg {
		if _, _, err := b.g.Run(gitx.Opts{GitDir: gitDir}, "config", kv[0], kv[1]); err != nil {
			return nil, cloakerr.New(cloakerr.LocalGit, "configure backend mirror", err)
		}
	}
	return b, nil
}

// disablePartial removes the promisor/filter configuration after a host
// rejected filtering, so subsequent fetches are full.
func (b *Backend) disablePartial() {
	b.partial = false
	for _, key := range []string{"remote.origin.promisor", "remote.origin.partialclonefilter"} {
		_, _, _ = b.g.Run(gitx.Opts{GitDir: b.gitDir}, "config", "--unset", key)
	}
	b.log.Warn("host does not support partial fetch (blob:none); falling back to full fetches; consolidated packs will re-download")
}

// Fetch updates the mirror from the host. It returns the backend branch tip
// oid, or empty=true when the branch does not exist yet (fresh remote).
func (b *Backend) Fetch() (head string, empty bool, err error) {
	args := []string{"fetch", "--no-tags"}
	if b.partial {
		args = append(args, "--filter="+partialFilter)
	}
	args = append(args, "origin")
	_, stderr, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Interactive: stdinIsTTY()}, args...)
	if err != nil {
		return b.classifyFetchErr(stderr, err)
	}
	head, err = b.g.Out(gitx.Opts{GitDir: b.gitDir}, "rev-parse", "--verify", remoteHeadRef)
	if err != nil {
		// Fetch succeeded but the ref is absent: empty remote repository.
		return "", true, nil
	}
	return head, false, nil
}

// classifyFetchErr maps a failed backend fetch to its Fetch result. A rejected
// partial filter triggers a one-time fallback to a full fetch (retrying the
// whole operation); a missing remote ref means the repository is empty;
// anything else is reported as a transport error.
func (b *Backend) classifyFetchErr(stderr string, err error) (head string, empty bool, _ error) {
	low := strings.ToLower(stderr)
	if b.partial && filterRejectedRe.MatchString(stderr) {
		b.disablePartial()
		return b.Fetch()
	}
	if strings.Contains(low, "couldn't find remote ref") ||
		strings.Contains(low, "no matching refs") {
		return "", true, nil
	}
	return "", false, gitx.ClassifyTransport("fetch backend branch", err)
}

// maxManifestBytes bounds how much of a manifest-sized blob ReadBlobBytes will
// buffer. The host serves the (untrusted) ciphertext, so without a cap a
// malicious or broken host could force unbounded memory by serving a giant
// manifest.age. 16 MiB is far above any honest manifest (one short JSON record
// per live pack, capped at manifest.maxPacks) yet bounds the read.
const maxManifestBytes = 1 << 24

// ReadBlobBytes returns the full content of <commit>:<path> (manifest-sized
// blobs only; packs stream via ReadBlob). The read is bounded to
// maxManifestBytes; an oversized blob is reported rather than buffered whole.
func (b *Backend) ReadBlobBytes(commit, path string) ([]byte, error) {
	var buf strings.Builder
	cap := &cappingWriter{w: &buf, limit: maxManifestBytes}
	if err := b.ReadBlob(commit, path, cap); err != nil {
		return nil, err
	}
	if cap.overflow {
		return nil, cloakerr.New(cloakerr.Tamper, "read remote blob "+path,
			fmt.Errorf("blob exceeds maximum size %d bytes", int64(maxManifestBytes)))
	}
	return []byte(buf.String()), nil
}

// ReadBlob streams the content of <commit>:<path> into dst. With the
// partial mirror, missing blobs are fetched lazily by git's promisor
// machinery during this call; if that machinery fails on this host and
// nothing has been written to dst yet, the mirror falls back to a full
// fetch once and retries before reporting tamper.
func (b *Backend) ReadBlob(commit, path string, dst io.Writer) error {
	cw := &countingWriter{w: dst}
	_, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Stdout: cw},
		"cat-file", "blob", commit+":"+path)
	if err != nil && b.partial && cw.n == 0 {
		b.log.Warn("blob read failed under partial mirror; retrying with a full fetch", "path", path)
		b.disablePartial()
		_, _, ferr := b.Fetch()
		if ferr != nil {
			return ferr // already transport-classified by Fetch
		}
		_, _, err = b.g.Run(gitx.Opts{GitDir: b.gitDir, Stdout: cw},
			"cat-file", "blob", commit+":"+path)
	}
	if err != nil {
		return classifyBlobRead(path, err)
	}
	return nil
}

// classifyBlobRead maps a blob read failure. Lazy promisor fetches run
// inside the cat-file call, so a network or auth outage surfaces here; it
// must report as transport, not tamper, or flaky networks would fire false
// TAMPER alarms that a sync wrapper escalates instead of retrying. Only a
// failure that is not transport-classifiable means content the manifest
// promised is unreadable, which is the tamper taxonomy.
func classifyBlobRead(path string, err error) error {
	// Classify against client-origin diagnostics only: a withholding host can
	// inject "remote:" sideband text (e.g. "connection reset") that git relays
	// into stderr, which would otherwise downgrade a genuine missing-blob
	// Tamper into a retryable Network error. Strip that host-controlled text
	// first; the original err is still wrapped for context.
	classifyErr := err
	var ge *gitx.GitError
	if errors.As(err, &ge) {
		sanitized := *ge
		sanitized.Stderr = gitx.StripServerSideband(ge.Stderr)
		classifyErr = &sanitized
	}
	terr := gitx.ClassifyTransport("read remote blob "+path, classifyErr)
	if kind, ok := cloakerr.KindOf(terr); ok && kind != cloakerr.LocalGit {
		return terr
	}
	return cloakerr.New(cloakerr.Tamper, "read remote blob "+path,
		fmt.Errorf("blob listed by manifest is unreadable: %w", err))
}

// countingWriter tracks whether any bytes reached dst (retry safety).
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// cappingWriter forwards to w until limit bytes have been written, then
// discards the rest and records overflow. It always reports a full write so
// the streaming git process runs to completion (memory stays bounded by the
// discard) and the caller can distinguish overflow from a transport failure.
type cappingWriter struct {
	w        io.Writer
	n        int64
	limit    int64
	overflow bool
}

func (c *cappingWriter) Write(p []byte) (int, error) {
	if c.overflow {
		return len(p), nil
	}
	room := c.limit - c.n
	if room >= int64(len(p)) {
		// Fits within the cap: forward the whole chunk.
		if wn, err := c.writeChunk(p); err != nil {
			return wn, err
		}
		return len(p), nil
	}
	// Exceeds the cap: forward what still fits, discard the rest, and record
	// the overflow so later writes are acknowledged but dropped.
	if room > 0 {
		if wn, err := c.writeChunk(p[:room]); err != nil {
			return wn, err
		}
	}
	c.overflow = true
	return len(p), nil
}

// writeChunk forwards b to the underlying writer and accumulates the bytes
// actually written, giving the two Write branches one place to keep n in sync
// with the destination.
func (c *cappingWriter) writeChunk(b []byte) (int, error) {
	wn, err := c.w.Write(b)
	c.n += int64(wn)
	return wn, err
}

// PackBlobOIDs maps pack id -> blob oid for every pack in the commit's
// packs/ subtree, so a new commit's tree can reuse the existing blobs
// without rehashing them.
func (b *Backend) PackBlobOIDs(commit string) (map[string]string, error) {
	if commit == "" {
		return map[string]string{}, nil
	}
	out, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir}, "ls-tree", commit+":packs")
	if err != nil {
		if isMissingPacksTree(err) {
			return map[string]string{}, nil
		}
		return nil, cloakerr.New(cloakerr.LocalGit, "list remote pack blobs", err)
	}
	return parsePackBlobTree(out), nil
}

// isMissingPacksTree reports whether err is the "this commit carries no packs/
// subtree" outcome of `git ls-tree <commit>:packs` (a manifest-only commit),
// which is a normal empty-pack-set result, not a failure. It matches git's "Not
// a valid object name" stderr and goes through errors.As (not a direct type
// assertion) so it still recognizes the sentinel if the error is ever wrapped
// further up the call chain, matching the errors.As idiom classifyBlobRead in
// this package already uses. Any other failure falls through and is reported as
// LocalGit, never silently collapsed to "no packs".
func isMissingPacksTree(err error) bool {
	var ge *gitx.GitError
	return errors.As(err, &ge) && strings.Contains(ge.Stderr, "Not a valid object name")
}

// parsePackBlobTree turns `git ls-tree <commit>:packs` output into a map from
// pack id (the <id>.age filename with the suffix stripped) to its blob oid,
// skipping any line that is not a well-formed "100644 blob <oid>\t<id>.age"
// tree entry.
func parsePackBlobTree(out string) map[string]string {
	oids := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		// Format: "100644 blob <oid>\t<id>.age"
		meta, name, found := strings.Cut(line, "\t")
		if !found {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) != 3 || fields[1] != "blob" {
			continue
		}
		oids[strings.TrimSuffix(name, ".age")] = fields[2]
	}
	return oids
}

// HashObject writes a blob into the mirror's object store and returns its oid.
func (b *Backend) HashObject(r io.Reader) (string, error) {
	out, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Stdin: r},
		"hash-object", "-w", "--stdin")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "hash-object", err)
	}
	return strings.TrimSpace(out), nil
}

// packTreeText serializes the pack-blob map into the `git mktree` input for the
// packs/ subtree: one "100644 blob <oid>\t<id>.age" entry per pack id, sorted by
// id so the same pack set always yields a byte-identical tree (and thus a
// reproducible commit identity, the compare-and-swap push relies on). It is the
// exact write-side inverse of parsePackBlobTree.
func packTreeText(packs map[string]string) string {
	var packTree strings.Builder
	ids := make([]string, 0, len(packs))
	for id := range packs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintf(&packTree, "100644 blob %s\t%s.age\n", packs[id], id)
	}
	return packTree.String()
}

// BuildCommit assembles the backend tree (manifest.age at the root, pack
// blobs under packs/) and creates a commit with deterministic identity and
// generation-derived timestamps. parent="" creates a root (squash) commit.
func (b *Backend) BuildCommit(parent, manifestOID string, packs map[string]string, generation uint64) (string, error) {
	packTreeOID, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Scrub: true,
		Stdin: strings.NewReader(packTreeText(packs))}, "mktree")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "mktree packs", err)
	}
	root := fmt.Sprintf("100644 blob %s\tmanifest.age\n040000 tree %s\tpacks\n",
		manifestOID, strings.TrimSpace(packTreeOID))
	rootOID, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Scrub: true,
		Stdin: strings.NewReader(root)}, "mktree")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "mktree root", err)
	}

	// Deterministic metadata: fixed identity, timestamp derived from the
	// generation (epoch base 2001-09-09) so commits leak no local clock.
	date := fmt.Sprintf("%d +0000", 1_000_000_000+generation)
	env := []string{
		"GIT_AUTHOR_NAME=cloak", "GIT_AUTHOR_EMAIL=cloak@cloak", "GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=cloak", "GIT_COMMITTER_EMAIL=cloak@cloak", "GIT_COMMITTER_DATE=" + date,
	}
	args := []string{"commit-tree", strings.TrimSpace(rootOID), "-m", "cloak"}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	commit, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Scrub: true, Env: env}, args...)
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "commit-tree", err)
	}
	return strings.TrimSpace(commit), nil
}

// PushResult classifies one backend push attempt.
type PushResult int

const (
	// PushOK: the ref updated.
	PushOK PushResult = iota
	// PushCASLost: the remote moved (non-fast-forward, stale info, or
	// failed ref lock); re-fetch and retry.
	PushCASLost
	// PushFailed: transport or other failure; see error.
	PushFailed
)

// PushFF pushes commit to the backend branch as a plain fast-forward push.
// Git's client FF check against the fresh advertisement plus the server's
// reference-changed-since-discovery rejection make this a compare-and-swap.
func (b *Backend) PushFF(commit string) (PushResult, error) {
	return b.push(commit, "")
}

// PushLease force-pushes commit (squash/repack/rekey) guarded by an
// explicit --force-with-lease expected value. Never a plain --force.
func (b *Backend) PushLease(commit, expectedOldOID string) (PushResult, error) {
	return b.push(commit, expectedOldOID)
}

// pushArgs builds the only two backend push command lines that can exist:
// plain fast-forward, or force-with-lease with an explicit expected value.
// A plain --force is structurally impossible; a unit test pins this.
func pushArgs(branch, commit, lease string) []string {
	args := []string{"push", "--porcelain"}
	if lease != "" {
		args = append(args, "--force-with-lease=refs/heads/"+branch+":"+lease)
	}
	return append(args, "origin", commit+":refs/heads/"+branch)
}

func (b *Backend) push(commit, lease string) (PushResult, error) {
	args := pushArgs(b.branch, commit, lease)
	stdout, stderr, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Interactive: stdinIsTTY()}, args...)
	switch res, marker := classifyPushResult(stdout, stderr, err); res {
	case PushOK:
		return PushOK, nil
	case PushCASLost:
		b.log.Info("backend push lost compare-and-swap", "marker", marker)
		return PushCASLost, nil
	default:
		return PushFailed, gitx.ClassifyTransport("push backend branch", err)
	}
}

// casLostMarkers are the substrings git prints (to stdout or stderr) when a push
// loses the compare-and-swap: the remote branch moved between discovery and the
// update, so the helper must re-fetch and retry rather than report a hard
// failure. The match is case-insensitive (the combined output is lowercased
// first), so these are written in lower case.
var casLostMarkers = []string{
	"non-fast-forward", "fetch first", "stale info",
	"cannot lock ref", "failed to update ref",
}

// classifyPushResult maps a backend push's outcome to a PushResult. runErr is
// the error git's push returned (nil means it succeeded, which short-circuits
// to PushOK before any output is scanned). On failure it scans the combined
// lowercased stdout/stderr for the first compare-and-swap-lost marker; the
// returned marker names the matched one (empty unless the result is
// PushCASLost) so the caller can log which signal it saw. A PushFailed result
// carries no marker and lets the caller classify the transport error.
func classifyPushResult(stdout, stderr string, runErr error) (res PushResult, marker string) {
	if runErr == nil {
		return PushOK, ""
	}
	combined := strings.ToLower(stdout + "\n" + stderr)
	for _, m := range casLostMarkers {
		if strings.Contains(combined, m) {
			return PushCASLost, m
		}
	}
	return PushFailed, ""
}
