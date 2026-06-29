// Package state manages cloak's per-remote local state under
// .git/cloak/<remote>/: the invocation lock (flock), the rollback pin
// (highest accepted generation + manifest ciphertext hash), the applied-pack
// set, the backend mirror location, temp space, and the debug log path. All
// state is reconstructible from the remote plus the key; deleting the
// directory degrades rollback protection to trust-on-first-use.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

// isSafeName reports whether s is a non-empty string of only [A-Za-z0-9._-],
// the character whitelist for using a remote name directly as a state dir name
// (anything else is hashed instead). Exact non-regex equivalent of
// `^[A-Za-z0-9._-]+$`.
func isSafeName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
			// allowed
		default:
			return false
		}
	}
	return true
}

// DirName returns the state directory name for a helper invocation:
// the remote name when git passed one, else a hash of the URL. "." and
// ".." pass the character whitelist but would escape the cloak/ directory
// (git refuses them as remote names, but the helper can be invoked
// directly), so they fall through to the URL hash.
func DirName(remoteName, url string) string {
	if remoteName != "" && remoteName != url && remoteName != "." && remoteName != ".." &&
		isSafeName(remoteName) {
		return remoteName
	}
	sum := sha256.Sum256([]byte(url))
	return "url-" + hex.EncodeToString(sum[:8])
}

// Dir is an opened per-remote state directory.
type Dir struct {
	Root string
}

// Open resolves (and creates) the state directory for the remote under the
// repository's common git dir. When a named remote's directory is missing
// but a url-hash directory for the same URL exists (created by clone before
// the remote had a name), the old directory is adopted by rename so the
// TOFU pin and applied set survive.
func Open(gitCommonDir, remoteName, url string) (*Dir, error) {
	base := filepath.Join(gitCommonDir, "cloak")
	name := DirName(remoteName, url)
	root := filepath.Join(base, name)
	if err := adoptURLHashDir(base, name, root, url); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o700); err != nil {
		return nil, err
	}
	return &Dir{Root: root}, nil
}

// adoptURLHashDir renames a pre-existing url-hash state dir into root so the
// TOFU pin and applied set created by clone (before the remote had a name)
// survive once the remote is named. It is a no-op unless the remote now has a
// name (name differs from the url hash), root does not yet exist, and a
// url-hash dir is present.
func adoptURLHashDir(base, name, root, url string) error {
	if name == DirName("", url) {
		return nil
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		return nil
	}
	hashed := filepath.Join(base, DirName("", url))
	if _, err := os.Stat(hashed); err != nil {
		return nil
	}
	if err := os.Rename(hashed, root); err != nil {
		// A discarded rename failure would silently abandon the old dir's TOFU
		// pin and applied set, downgrading the remote to trust-on-first-use
		// without telling anyone. Tolerate only the benign race where another
		// process already created root; surface any other failure instead of
		// proceeding onto a fresh empty state dir.
		if _, statErr := os.Stat(root); statErr != nil {
			return fmt.Errorf("adopt url-hash state dir %q -> %q: %w", hashed, root, err)
		}
	}
	return nil
}

// Lock takes an exclusive flock serializing helper and CLI invocations for
// this remote. The returned release function must be called on exit; it
// reports the first of the unlock/close errors so the caller can log a
// failed release (an undetected unlock failure or fd leak) instead of
// silently dropping it.
func (d *Dir) Lock() (func() error, error) {
	f, err := os.OpenFile(filepath.Join(d.Root, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() error {
		unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closeErr := f.Close()
		if unlockErr != nil {
			return unlockErr
		}
		return closeErr
	}, nil
}

// BackendGitDir is the bare mirror of the backend branch.
func (d *Dir) BackendGitDir() string { return filepath.Join(d.Root, "backend.git") }

// TmpDir is scratch space inside the state directory (same filesystem as
// the local repo, plaintext allowed: the local repo is plaintext anyway).
func (d *Dir) TmpDir() string { return filepath.Join(d.Root, "tmp") }

// LogPath is the per-remote debug log file.
func (d *Dir) LogPath() string { return filepath.Join(d.Root, "log") }

// readStateFile reads a file under the state directory. ok is false (with a
// nil error) when the file does not exist yet -- the first-contact case every
// caller treats as "no record".
func (d *Dir) readStateFile(name string) ([]byte, bool, error) {
	b, err := os.ReadFile(filepath.Join(d.Root, name)) // #nosec G304 -- per-remote state dir Root + a fixed internal filename; name is never caller- or remote-controlled
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read state file %q: %w", name, err)
	}
	return b, true, nil
}

// writeStateFile atomically and durably replaces the state file destName: it
// writes the content to tmpName under TmpDir (same filesystem), fsyncs it,
// renames it into place, then fsyncs the directory. The temp-file-then-rename
// makes the replacement atomic (a reader never sees a torn file); the two
// fsyncs make it crash-safe, so an interrupted push cannot leave the pin or
// repo-id file existing-but-zero-length or reverted to stale content after a
// power loss or kernel crash.
func (d *Dir) writeStateFile(tmpName, destName string, content []byte) error {
	tmp := filepath.Join(d.TmpDir(), tmpName)
	if err := writeFileSync(tmp, content, 0o600); err != nil {
		return fmt.Errorf("write state file %q: %w", destName, err)
	}
	if err := os.Rename(tmp, filepath.Join(d.Root, destName)); err != nil {
		return fmt.Errorf("write state file %q: %w", destName, err)
	}
	if err := syncDir(d.Root); err != nil {
		return fmt.Errorf("write state file %q: %w", destName, err)
	}
	return nil
}

// writeFileSync writes content to path (creating or truncating) and fsyncs the
// file's data to disk before returning, so a crash after the caller renames it
// into place cannot surface a zero-length or partially written file. Mirrors
// the fsync-before-success discipline keystore.saveFile uses for the key file.
func writeFileSync(path string, content []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) // #nosec G304 -- path is TmpDir() + a fixed internal temp name; never caller- or remote-controlled
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// syncDir fsyncs a directory so a rename into it is durable across a crash:
// without it the renamed entry can be lost on power loss even though the
// file's own data was fsynced.
func syncDir(path string) error {
	f, err := os.Open(path) // #nosec G304 -- path is the per-remote state dir Root; never caller- or remote-controlled
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// removeStateFile durably deletes the named state file: it removes the file
// then fsyncs the parent directory so the deletion survives a crash, the
// mirror of writeStateFile's post-rename dir fsync. Without it a power loss in
// the instant after os.Remove could resurrect a just-cleared pin, re-raising a
// rollback/repo-change alarm the operator had already accepted. An
// already-absent file is success (and needs no sync: nothing changed on disk)
// so callers can clear a record idempotently.
func (d *Dir) removeStateFile(name string) error {
	err := os.Remove(filepath.Join(d.Root, name))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove state file %q: %w", name, err)
	}
	if err := syncDir(d.Root); err != nil {
		return fmt.Errorf("remove state file %q: %w", name, err)
	}
	return nil
}

// Pin is the rollback-protection record.
type Pin struct {
	Generation   uint64
	ManifestHash string
}

const pinFile = "generation"

// LoadPin returns the stored pin; ok=false on first contact.
func (d *Dir) LoadPin() (Pin, bool, error) {
	b, ok, err := d.readStateFile(pinFile)
	if err != nil || !ok {
		return Pin{}, ok, err
	}
	var p Pin
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d %s", &p.Generation, &p.ManifestHash); err != nil {
		return Pin{}, false, fmt.Errorf("corrupt pin file %s: %w", filepath.Join(d.Root, pinFile), err)
	}
	// The pin's manifest hash is a SHA-256 ciphertext digest (ciphertextHash),
	// always exactly 64 lowercase hex. Reject any other shape as corrupt rather
	// than silently normalizing it (e.g. a short "deadbeef"), so a malformed or
	// tampered local pin fails closed instead of being accepted as a valid
	// rollback anchor and quietly overwritten by the next higher-generation state.
	if !manifest.IsLowerHex(p.ManifestHash, 64) {
		return Pin{}, false, fmt.Errorf("corrupt pin file %s: manifest hash is not 64 lowercase hex",
			filepath.Join(d.Root, pinFile))
	}
	return p, true, nil
}

// SavePin atomically persists the pin.
func (d *Dir) SavePin(p Pin) error {
	return d.writeStateFile("pin", pinFile, []byte(fmt.Sprintf("%d %s\n", p.Generation, p.ManifestHash)))
}

// SavePins advances the rollback pin and the repo-id pin together. It
// fsync-writes BOTH temp files before renaming EITHER into place, so the
// realistic failure (an error writing the second record, e.g. a full disk)
// leaves both prior pins untouched rather than persisting a generation pin
// without its repo-id pin -- a half-written state that would silently drop
// repo-identity protection to trust-on-first-use while rollback protection
// stayed enforced (CheckRepoID accepts a missing pin as TOFU; CheckPin still
// enforces). The two renames are adjacent metadata ops on the same directory;
// a crash strictly between them is still possible (closing that fully would
// need a single combined pin file, i.e. an on-disk format change), but the
// window shrinks from the second file's write+rename to between two renames.
// On-disk layout is unchanged: the same generation and repoid files with
// serialization byte-identical to SavePin/SaveRepoID.
func (d *Dir) SavePins(p Pin, repoID string) error {
	pinTmp := filepath.Join(d.TmpDir(), "pin")
	ridTmp := filepath.Join(d.TmpDir(), "repoid")
	if err := writeFileSync(pinTmp, []byte(fmt.Sprintf("%d %s\n", p.Generation, p.ManifestHash)), 0o600); err != nil {
		return fmt.Errorf("write state file %q: %w", pinFile, err)
	}
	if err := writeFileSync(ridTmp, []byte(repoID+"\n"), 0o600); err != nil {
		return fmt.Errorf("write state file %q: %w", repoIDFile, err)
	}
	if err := os.Rename(pinTmp, filepath.Join(d.Root, pinFile)); err != nil {
		return fmt.Errorf("write state file %q: %w", pinFile, err)
	}
	if err := os.Rename(ridTmp, filepath.Join(d.Root, repoIDFile)); err != nil {
		return fmt.Errorf("write state file %q: %w", repoIDFile, err)
	}
	if err := syncDir(d.Root); err != nil {
		return fmt.Errorf("write state file %q: %w", pinFile, err)
	}
	return nil
}

// CheckPin enforces rollback protection for a validated remote manifest:
// higher generation is accepted (and should then be pinned), equal
// generation must be byte-identical ciphertext, lower generation is a
// rollback alarm. A remote that became empty while a pin exists is also a
// rollback alarm.
func (d *Dir) CheckPin(m *manifest.Manifest, manifestHash string) error {
	pin, ok, err := d.LoadPin()
	if err != nil {
		return err
	}
	if !ok {
		return nil // trust-on-first-use
	}
	if m == nil {
		return cloakerr.Newf(cloakerr.Rollback, "remote state",
			"remote is empty but generation %d was previously seen (host rolled back or wiped the repo); run `git cloak accept-rollback` if this is expected", pin.Generation)
	}
	switch {
	case m.Generation > pin.Generation:
		return nil
	case m.Generation == pin.Generation:
		if manifestHash != pin.ManifestHash {
			return cloakerr.Newf(cloakerr.Tamper, "remote state",
				"remote manifest changed without a generation bump (generation %d, hash %s != pinned %s)",
				m.Generation, manifestHash, pin.ManifestHash)
		}
		return nil
	default:
		return cloakerr.Newf(cloakerr.Rollback, "remote state",
			"remote generation %d is older than last seen %d (host served stale or replayed state); run `git cloak accept-rollback` if this is expected",
			m.Generation, pin.Generation)
	}
}

// ClearPin removes the rollback pin, returning protection to
// trust-on-first-use for the next fetch. Only `git cloak accept-rollback`
// calls this; it is deliberately not reachable via configuration.
func (d *Dir) ClearPin() error { return d.removeStateFile(pinFile) }

const repoIDFile = "repoid"

// LoadRepoID returns the locally pinned repository identity; ok=false on
// first contact (no pin yet).
func (d *Dir) LoadRepoID() (string, bool, error) {
	b, ok, err := d.readStateFile(repoIDFile)
	if err != nil || !ok {
		return "", ok, err
	}
	return strings.TrimSpace(string(b)), true, nil
}

// SaveRepoID atomically persists the repository-identity pin.
func (d *Dir) SaveRepoID(id string) error {
	return d.writeStateFile("repoid", repoIDFile, []byte(id+"\n"))
}

// ClearRepoID removes the repo-identity pin, returning to trust-on-first-use.
// Only `git cloak accept-repo-change` calls this; like ClearPin it is not
// reachable via configuration.
func (d *Dir) ClearRepoID() error { return d.removeStateFile(repoIDFile) }

// CheckRepoID enforces repository-identity trust-on-first-use: a missing
// local pin accepts (the caller pins once the state is fully applied), a
// matching id passes, and a changed id is a substitution alarm. An empty
// remote carries no manifest, so there is nothing to check.
func (d *Dir) CheckRepoID(m *manifest.Manifest) error {
	if m == nil {
		return nil
	}
	pinned, ok, err := d.LoadRepoID()
	if err != nil {
		return err
	}
	if !ok {
		return nil // trust-on-first-use
	}
	if m.RepoID != pinned {
		return cloakerr.Newf(cloakerr.Tamper, "remote state",
			"REPO IDENTITY MISMATCH: remote repo id %s does not match pinned %s (the host served a different repository, or this remote points at the wrong URL); run `git cloak accept-repo-change` if this is expected",
			m.RepoID, pinned)
	}
	return nil
}

const appliedFile = "applied"

// AppliedSet returns the pack ids already indexed into the local repo.
func (d *Dir) AppliedSet() (map[string]bool, error) {
	out := map[string]bool{}
	b, ok, err := d.readStateFile(appliedFile)
	if err != nil {
		return nil, err
	}
	if !ok {
		return out, nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out[line] = true
		}
	}
	return out, nil
}

// MarkApplied records pack ids as already indexed into the local repo. It
// reads the current set and rewrites the file atomically and durably via
// writeStateFile (temp file, fsync, rename, dir fsync), so an interrupted
// write can never leave a torn line or a lost record: a reader sees either the
// old set or the new one, never a half-written id. Callers hold the per-remote
// flock (Dir.Lock), so the read-modify-write has no concurrent writer to race.
func (d *Dir) MarkApplied(ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	out, _, err := d.readStateFile(appliedFile)
	if err != nil {
		return err
	}
	// The sole writer (this function) always terminates every id with '\n', so
	// a well-formed file ends in a newline; the guard only re-establishes the
	// line boundary if an older non-atomic write left a torn final line.
	if n := len(out); n > 0 && out[n-1] != '\n' {
		out = append(out, '\n')
	}
	for _, id := range ids {
		out = append(out, id...)
		out = append(out, '\n')
	}
	return d.writeStateFile("applied", appliedFile, out)
}
