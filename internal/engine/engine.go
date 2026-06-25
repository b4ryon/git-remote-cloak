// Package engine implements cloak's push/fetch algorithms over the backend
// mirror, the manifest, and git plumbing in the local repository: remote
// state validation (AEAD, rollback pin), pack application on fetch, and
// (from M3) pack creation with chained-CAS pushes and retry. It contains no
// protocol I/O; the helper package drives it.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/config"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
	"github.com/b4ryon/git-remote-cloak/internal/state"
)

// Engine binds the local repository, per-remote state, backend mirror, and
// master key together for one helper or CLI invocation.
type Engine struct {
	G           *gitx.G
	LocalGitDir string
	St          *state.Dir
	Be          *backend.Backend
	Key         keystore.Key
	Cfg         config.Config
	Log         *slog.Logger
}

// RemoteState is the validated view of the remote after one fetch.
type RemoteState struct {
	// Head is the backend branch tip commit ("" when the remote is empty).
	Head string
	// Manifest is the decrypted, validated manifest (nil when empty).
	Manifest *manifest.Manifest
	// ManifestHash is the SHA-256 hex of the manifest ciphertext.
	ManifestHash string
}

// ciphertextHash returns the SHA-256 hex digest of a manifest ciphertext. It
// is the value recorded as the rollback pin's ManifestHash, so the read path
// (LoadRemoteState, which checks the pin) and the write path
// (buildBackendCommit, which stores it) MUST compute it identically for a
// freshly pushed pin to match on the next fetch; centralizing it here guarantees
// the two cannot drift apart.
func ciphertextHash(ct []byte) string {
	sum := sha256.Sum256(ct)
	return hex.EncodeToString(sum[:])
}

// LoadRemoteState fetches the backend branch, decrypts and validates the
// manifest, and enforces the rollback pin and repository-identity TOFU. It
// does NOT advance the local pins: those are persisted by CommitPin only
// after the state is fully fetched, verified, and applied, so a host serving
// a valid manifest while withholding or corrupting its packs cannot move the
// pin off honest state.
func (e *Engine) LoadRemoteState() (*RemoteState, error) {
	head, empty, err := e.Be.Fetch()
	if err != nil {
		return nil, err
	}
	if empty {
		if err := e.St.CheckPin(nil, ""); err != nil {
			return nil, err
		}
		e.Log.Info("remote is empty (no backend branch yet)")
		return &RemoteState{}, nil
	}
	return e.loadPopulatedState(head)
}

// loadPopulatedState reads, decrypts, decodes, and pin/identity-validates the
// manifest at a non-empty backend head. It is the populated-remote half of
// LoadRemoteState, split out so the empty-remote short-circuit and this
// decrypt-and-validate pipeline are each below the complexity threshold.
func (e *Engine) loadPopulatedState(head string) (*RemoteState, error) {
	ct, err := e.Be.ReadBlobBytes(head, "manifest.age")
	if err != nil {
		return nil, err
	}
	hash := ciphertextHash(ct)
	pt, err := agecrypt.DecryptBytes(e.Key, ct)
	if err != nil {
		// The manifest is the first thing decrypted on every fetch/clone, and at
		// the AEAD layer a wrong master key is indistinguishable from genuine
		// tampering. On first contact the overwhelmingly common cause is a
		// wrong/missing key, so steer the user there (still Tamper-classified).
		return nil, cloakerr.WithHintOn(err,
			"the manifest is the first thing decrypted, and a wrong master key is indistinguishable from tamper here; verify `git config cloak.keyRef` and re-import the key with `git cloak key import` if this is a new machine")
	}
	m, err := manifest.Decode(pt)
	if err != nil {
		// The bytes already passed AEAD verification, so this is NOT tampering:
		// it is a manifest this build cannot parse (version/format skew).
		return nil, cloakerr.Newfh(cloakerr.Protocol, "decode manifest",
			"the remote decrypted correctly but its manifest is not understood by this version; upgrade git-remote-cloak (the other machine may be on a newer format)",
			"remote manifest invalid: %v", err)
	}
	if err := e.St.CheckPin(m, hash); err != nil {
		return nil, err
	}
	if err := e.St.CheckRepoID(m); err != nil {
		return nil, err
	}
	e.Log.Info("remote state validated", "generation", m.Generation,
		"refs", len(m.Refs), "packs", len(m.Packs))
	return &RemoteState{Head: head, Manifest: m, ManifestHash: hash}, nil
}

// CommitPin persists the rollback pin and the repository-identity pin for a
// remote state that has been fully fetched, verified, and applied. It is the
// single point at which the local pins advance: callers invoke it only after
// FetchApply succeeded and every requested object is present, so a host that
// withholds or corrupts packs never moves the pins. No-op for an empty
// remote (no manifest to pin).
func (e *Engine) CommitPin(rs *RemoteState) error {
	if rs == nil || rs.Manifest == nil {
		return nil
	}
	if err := e.St.SavePin(state.Pin{Generation: rs.Manifest.Generation, ManifestHash: rs.ManifestHash}); err != nil {
		return err
	}
	return e.St.SaveRepoID(rs.Manifest.RepoID)
}

// HaveObject reports whether the local repository has the object.
func (e *Engine) HaveObject(oid string) bool {
	_, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir}, "cat-file", "-e", oid)
	return err == nil
}

// HasObjectClosure reports whether the local repository contains the COMPLETE
// set of objects reachable from every given tip, not merely the tip objects
// themselves (which is all HaveObject checks). It walks each tip with
// rev-list --objects --missing=print and reports complete only when rev-list
// succeeds and names no missing object. Any uncertainty (a rev-list error, or
// any reported-missing object) returns false, so a caller that uses this to
// skip a download fails safe by downloading instead.
func (e *Engine) HasObjectClosure(oids []string) bool {
	if len(oids) == 0 {
		return true
	}
	args := append([]string{"rev-list", "--objects", "--missing=print"}, oids...)
	out, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir}, args...)
	if err != nil {
		return false
	}
	return !revListReportsMissing(out)
}

// revListReportsMissing reports whether git rev-list --objects --missing=print
// output names any missing object: a line that, after trimming surrounding
// whitespace, begins with "?". HasObjectClosure treats any such line as the
// closure being incomplete and fails safe by downloading the pack instead, so a
// parse that under-reports a "?" line would skip a download the local repo
// actually needs. Extracted as a pure function so it can be fuzzed without a
// git host.
func revListReportsMissing(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "?") {
			return true
		}
	}
	return false
}

// FetchApply downloads and indexes every manifest pack the local repo has
// not applied yet (honoring consolidation lineage via Replaces), verifying
// each blob's SHA-256 against its manifest id and decrypting fully BEFORE
// anything reaches git index-pack, so tampered data never enters the local
// object store. Returns the .keep file paths created by index-pack, for the
// protocol's lock lines.
func (e *Engine) FetchApply(rs *RemoteState) (keepFiles []string, err error) {
	if rs.Manifest == nil {
		return nil, nil
	}
	applied, err := e.St.AppliedSet()
	if err != nil {
		return nil, err
	}
	keepFiles, newlyApplied, err := e.applyManifestPacks(rs, applied)
	if err != nil {
		return nil, err
	}
	if err := e.St.MarkApplied(newlyApplied...); err != nil {
		return nil, err
	}
	return keepFiles, nil
}

// applyManifestPacks walks the manifest packs in order, downloading and
// indexing each not-yet-applied pack unless it can be skipped, and returns the
// .keep files created plus the ids to mark applied. The applied map is updated
// as it goes so a later pack's predecessor check sees earlier packs.
func (e *Engine) applyManifestPacks(rs *RemoteState, applied map[string]bool) (keepFiles, newlyApplied []string, err error) {
	closure := e.lazyClosure(rs.Manifest.Refs)
	for _, p := range rs.Manifest.Packs {
		if applied[p.ID] {
			continue
		}
		keep, err := e.downloadUnlessSkippable(rs.Head, p, applied, closure)
		if err != nil {
			return nil, nil, err
		}
		if keep != "" {
			keepFiles = append(keepFiles, keep)
		}
		newlyApplied = append(newlyApplied, p.ID)
		applied[p.ID] = true
	}
	return keepFiles, newlyApplied, nil
}

// downloadUnlessSkippable downloads and indexes pack p unless packSkippable
// reports it can be marked applied without downloading, in which case it
// returns an empty keep path. The returned keep is the .keep file created by
// index-pack (empty when the pack was skipped or carried no keep file).
func (e *Engine) downloadUnlessSkippable(head string, p manifest.Pack, applied map[string]bool, closure func() bool) (keep string, err error) {
	if e.packSkippable(p, applied, closure) {
		return "", nil
	}
	return e.applyPack(head, p)
}

// packSkippable reports whether pack p can be marked applied without
// downloading it: either every pack it replaces is already applied, or the
// local repo already holds the complete object closure of every ref tip.
func (e *Engine) packSkippable(p manifest.Pack, applied map[string]bool, closure func() bool) bool {
	if replacesCovered(p, applied) {
		e.Log.Info("pack covered by applied predecessors; skipping download",
			"pack", p.ID[:12], "replaces", len(p.Replaces))
		return true
	}
	// Local repo already holds every object this pack would deliver.
	return closure()
}

// replacesCovered reports whether pack p supersedes earlier packs and every
// one of them is already applied locally, so p delivers nothing new.
func replacesCovered(p manifest.Pack, applied map[string]bool) bool {
	if len(p.Replaces) == 0 {
		return false
	}
	for _, r := range p.Replaces {
		if !applied[r] {
			return false
		}
	}
	return true
}

// lazyClosure returns a memoized predicate reporting whether the local repo
// holds the COMPLETE object closure of every manifest ref tip, not merely the
// tips. A tip can be present while its history is not (e.g. an interrupted
// prior index-pack, a graft, a partial prune); marking a pack applied in that
// case would permanently skip the pack that carries the missing objects, since
// the applied set is never re-examined. The check is computed at most once, and
// only when a pack actually needs the shortcut, so the common case where every
// pack is already applied pays nothing.
func (e *Engine) lazyClosure(refs map[string]string) func() bool {
	tips := make([]string, 0, len(refs))
	for _, oid := range refs {
		tips = append(tips, oid)
	}
	checked, complete := false, false
	return func() bool {
		if !checked {
			complete = e.HasObjectClosure(tips)
			checked = true
		}
		return complete
	}
}

// packTamperHint is attached to pack verify/decrypt failures. Unlike the
// manifest, a pack is only reached after the manifest already decrypted under
// the same key, so the key is provably correct and a failure here points at
// the host serving bad data rather than a wrong key.
const packTamperHint = "the manifest decrypted under this key but this pack did not, so the key is correct; the host likely served corrupted or tampered pack data. Re-fetch and check the debug log"

// downloadVerifyPack downloads packs/<id>.age from the backend commit head
// into ctPath, hashing the ciphertext as it streams, and fails if the hash
// does not match the manifest pack id (the host served corrupted or tampered
// data, since the key is already proven correct by the manifest decrypt).
func (e *Engine) downloadVerifyPack(head, ctPath string, p manifest.Pack) error {
	f, err := os.OpenFile(ctPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	if err := e.Be.ReadBlob(head, "packs/"+p.ID+".age", io.MultiWriter(f, hasher)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != p.ID {
		return cloakerr.Newf(cloakerr.Tamper, "verify pack "+p.ID[:12],
			"ciphertext hash %s does not match manifest id %s", got, p.ID).WithHint(packTamperHint)
	}
	return nil
}

// applyPack downloads packs/<id>.age, verifies and decrypts it, and feeds
// the plaintext pack to git index-pack in the local repository.
func (e *Engine) applyPack(head string, p manifest.Pack) (keepFile string, err error) {
	short := p.ID[:12]
	ctPath := filepath.Join(e.St.TmpDir(), "pack-"+short+".age")
	ptPath := filepath.Join(e.St.TmpDir(), "pack-"+short+".pack")
	defer os.Remove(ctPath)
	defer os.Remove(ptPath)

	if err := e.downloadVerifyPack(head, ctPath, p); err != nil {
		return "", err
	}
	if err := e.decryptPackTo(ctPath, ptPath); err != nil {
		return "", err
	}
	return e.indexPackFile(ptPath, short, p.Size)
}

// decryptPackTo decrypts the age ciphertext at ctPath and writes the
// plaintext pack to ptPath, classifying AEAD failures as Tamper.
func (e *Engine) decryptPackTo(ctPath, ptPath string) error {
	ct, err := os.Open(ctPath)
	if err != nil {
		return err
	}
	defer ct.Close()
	plain, err := agecrypt.Decrypt(ct, e.Key)
	if err != nil {
		return cloakerr.WithHintOn(err, packTamperHint)
	}
	ptFile, err := os.OpenFile(ptPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(ptFile, plain); err != nil {
		ptFile.Close()
		return cloakerr.WithHintOn(err, packTamperHint) // Tamper-classified by agecrypt on AEAD failure
	}
	return ptFile.Close()
}

// indexPackFile feeds the plaintext pack at ptPath to git index-pack in the
// local repo and returns the .keep file it created (empty if none).
func (e *Engine) indexPackFile(ptPath, short string, size int64) (keepFile string, err error) {
	pt, err := os.Open(ptPath)
	if err != nil {
		return "", err
	}
	defer pt.Close()
	out, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir, Stdin: pt},
		"index-pack", "--stdin", "--keep=cloak")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "index pack "+short, err)
	}
	e.Log.Info("applied pack", "pack", short, "ciphertext_bytes", size)
	return keepFileFromIndexPack(e.LocalGitDir, out), nil
}

// keepFileFromIndexPack parses `git index-pack --keep=cloak` stdout for the
// first "keep\t<hash>" line and returns the matching .keep lock-file path
// (gitDir/objects/pack/pack-<hash>.keep), or "" when no keep line is present.
// index-pack prints exactly one such line per kept pack ("keep" then a tab then
// the pack sha); the returned path is what the helper reports to git as the
// fetch "lock" line (helper.go handleFetch), the marker that stops git from
// garbage-collecting the just-applied pack, so a mis-parse would drop a lock git
// needs or name the wrong file. Extracted from indexPackFile (behavior-
// preserving) so the parse is fuzz-reachable without a git host.
func keepFileFromIndexPack(gitDir, out string) string {
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		kind, hash, found := strings.Cut(strings.TrimSpace(line), "\t")
		if found && kind == "keep" {
			return filepath.Join(gitDir, "objects", "pack", "pack-"+hash+".keep")
		}
	}
	return ""
}

// HeadForList resolves the symref target to advertise for HEAD: the
// manifest head if valid, else main > master > first branch alphabetically.
func HeadForList(m *manifest.Manifest) string {
	if m == nil {
		return ""
	}
	if m.Head != "" {
		if _, ok := m.Refs[m.Head]; ok {
			return m.Head
		}
	}
	for _, cand := range []string{"refs/heads/main", "refs/heads/master"} {
		if _, ok := m.Refs[cand]; ok {
			return cand
		}
	}
	return firstBranch(m)
}

// firstBranch returns the alphabetically-first refs/heads/* ref in the
// manifest, or "" when the manifest advertises no branches. It is the final
// fallback for HeadForList once the manifest head and main/master are ruled out.
func firstBranch(m *manifest.Manifest) string {
	var branches []string
	for name := range m.Refs {
		if strings.HasPrefix(name, "refs/heads/") {
			branches = append(branches, name)
		}
	}
	if len(branches) == 0 {
		return ""
	}
	sort.Strings(branches)
	return branches[0]
}
