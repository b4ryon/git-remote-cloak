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
	ct, err := e.Be.ReadBlobBytes(head, "manifest.age")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(ct)
	hash := hex.EncodeToString(sum[:])
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
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "?") {
			return false
		}
	}
	return true
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

	// The no-download shortcut below is gated on the local repo already holding
	// the COMPLETE object closure of every manifest ref tip, not merely the
	// tips. A tip can be present while its history is not (e.g. an interrupted
	// prior index-pack, a graft, a partial prune); marking a pack applied in
	// that case would permanently skip the pack that carries the missing
	// objects, since the applied set is never re-examined. The closure check is
	// computed lazily (only when a pack actually needs the shortcut) so the
	// common case where every pack is already applied pays nothing.
	tips := make([]string, 0, len(rs.Manifest.Refs))
	for _, oid := range rs.Manifest.Refs {
		tips = append(tips, oid)
	}
	closureChecked, closureComplete := false, false

	var newlyApplied []string
	for _, p := range rs.Manifest.Packs {
		if applied[p.ID] {
			continue
		}
		if len(p.Replaces) > 0 {
			all := true
			for _, r := range p.Replaces {
				if !applied[r] {
					all = false
					break
				}
			}
			if all {
				e.Log.Info("pack covered by applied predecessors; skipping download",
					"pack", p.ID[:12], "replaces", len(p.Replaces))
				newlyApplied = append(newlyApplied, p.ID)
				applied[p.ID] = true
				continue
			}
		}
		if !closureChecked {
			closureComplete = e.HasObjectClosure(tips)
			closureChecked = true
		}
		if closureComplete {
			// Local repo already holds every object these packs would deliver.
			newlyApplied = append(newlyApplied, p.ID)
			applied[p.ID] = true
			continue
		}
		keep, err := e.applyPack(rs.Head, p)
		if err != nil {
			return nil, err
		}
		if keep != "" {
			keepFiles = append(keepFiles, keep)
		}
		newlyApplied = append(newlyApplied, p.ID)
		applied[p.ID] = true
	}
	if err := e.St.MarkApplied(newlyApplied...); err != nil {
		return nil, err
	}
	return keepFiles, nil
}

// packTamperHint is attached to pack verify/decrypt failures. Unlike the
// manifest, a pack is only reached after the manifest already decrypted under
// the same key, so the key is provably correct and a failure here points at
// the host serving bad data rather than a wrong key.
const packTamperHint = "the manifest decrypted under this key but this pack did not, so the key is correct; the host likely served corrupted or tampered pack data. Re-fetch and check the debug log"

// applyPack downloads packs/<id>.age, verifies and decrypts it, and feeds
// the plaintext pack to git index-pack in the local repository.
func (e *Engine) applyPack(head string, p manifest.Pack) (keepFile string, err error) {
	short := p.ID[:12]
	ctPath := filepath.Join(e.St.TmpDir(), "pack-"+short+".age")
	ptPath := filepath.Join(e.St.TmpDir(), "pack-"+short+".pack")
	defer os.Remove(ctPath)
	defer os.Remove(ptPath)

	ctFile, err := os.OpenFile(ctPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	if err := e.Be.ReadBlob(head, "packs/"+p.ID+".age", io.MultiWriter(ctFile, hasher)); err != nil {
		ctFile.Close()
		return "", err
	}
	if err := ctFile.Close(); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != p.ID {
		return "", cloakerr.Newf(cloakerr.Tamper, "verify pack "+short,
			"ciphertext hash %s does not match manifest id %s", got, p.ID).WithHint(packTamperHint)
	}

	ct, err := os.Open(ctPath)
	if err != nil {
		return "", err
	}
	defer ct.Close()
	plain, err := agecrypt.Decrypt(ct, e.Key)
	if err != nil {
		return "", cloakerr.WithHintOn(err, packTamperHint)
	}
	ptFile, err := os.OpenFile(ptPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(ptFile, plain); err != nil {
		ptFile.Close()
		return "", cloakerr.WithHintOn(err, packTamperHint) // Tamper-classified by agecrypt on AEAD failure
	}
	if err := ptFile.Close(); err != nil {
		return "", err
	}

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
	e.Log.Info("applied pack", "pack", short, "ciphertext_bytes", p.Size)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		kind, hash, found := strings.Cut(strings.TrimSpace(line), "\t")
		if found && kind == "keep" {
			return filepath.Join(e.LocalGitDir, "objects", "pack", "pack-"+hash+".keep"), nil
		}
	}
	return "", nil
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
