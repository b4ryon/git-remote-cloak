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
	"regexp"
	"strings"
	"syscall"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

var safeName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// DirName returns the state directory name for a helper invocation:
// the remote name when git passed one, else a hash of the URL. "." and
// ".." pass the character whitelist but would escape the cloak/ directory
// (git refuses them as remote names, but the helper can be invoked
// directly), so they fall through to the URL hash.
func DirName(remoteName, url string) string {
	if remoteName != "" && remoteName != url && remoteName != "." && remoteName != ".." &&
		safeName.MatchString(remoteName) {
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
	if name != DirName("", url) {
		hashed := filepath.Join(base, DirName("", url))
		if _, err := os.Stat(root); os.IsNotExist(err) {
			if _, err := os.Stat(hashed); err == nil {
				_ = os.Rename(hashed, root)
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o700); err != nil {
		return nil, err
	}
	return &Dir{Root: root}, nil
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
		f.Close()
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

// Pin is the rollback-protection record.
type Pin struct {
	Generation   uint64
	ManifestHash string
}

const pinFile = "generation"

// LoadPin returns the stored pin; ok=false on first contact.
func (d *Dir) LoadPin() (Pin, bool, error) {
	b, err := os.ReadFile(filepath.Join(d.Root, pinFile))
	if os.IsNotExist(err) {
		return Pin{}, false, nil
	}
	if err != nil {
		return Pin{}, false, err
	}
	var p Pin
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d %s", &p.Generation, &p.ManifestHash); err != nil {
		return Pin{}, false, fmt.Errorf("corrupt pin file %s: %w", filepath.Join(d.Root, pinFile), err)
	}
	return p, true, nil
}

// SavePin atomically persists the pin.
func (d *Dir) SavePin(p Pin) error {
	tmp := filepath.Join(d.TmpDir(), "pin")
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %s\n", p.Generation, p.ManifestHash)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d.Root, pinFile))
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
func (d *Dir) ClearPin() error {
	err := os.Remove(filepath.Join(d.Root, pinFile))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

const repoIDFile = "repoid"

// LoadRepoID returns the locally pinned repository identity; ok=false on
// first contact (no pin yet).
func (d *Dir) LoadRepoID() (string, bool, error) {
	b, err := os.ReadFile(filepath.Join(d.Root, repoIDFile))
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(string(b)), true, nil
}

// SaveRepoID atomically persists the repository-identity pin.
func (d *Dir) SaveRepoID(id string) error {
	tmp := filepath.Join(d.TmpDir(), "repoid")
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d.Root, repoIDFile))
}

// ClearRepoID removes the repo-identity pin, returning to trust-on-first-use.
// Only `git cloak accept-repo-change` calls this; like ClearPin it is not
// reachable via configuration.
func (d *Dir) ClearRepoID() error {
	err := os.Remove(filepath.Join(d.Root, repoIDFile))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

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
	b, err := os.ReadFile(filepath.Join(d.Root, appliedFile))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out[line] = true
		}
	}
	return out, nil
}

// MarkApplied appends pack ids to the applied set.
func (d *Dir) MarkApplied(ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(d.Root, appliedFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, id := range ids {
		if _, err := fmt.Fprintln(f, id); err != nil {
			return err
		}
	}
	return f.Close()
}
