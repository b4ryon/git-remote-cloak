// git-cloak debug seed-remote: builds a valid cloak backend branch on a
// host from a plain local repository, using the same backend write
// primitives the push path uses. Exists for milestone gates and the test
// harness (it lets the fetch path be developed and verified before the
// push path lands).
package cli

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/logx"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

func cmdDebugSeedRemote(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("debug seed-remote", stderr)
	ref := keyFlag(fs)
	from := fs.String("from", "", "plain source repository (required)")
	branch := fs.String("branch", "cloak", "backend branch name on the host")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *from == "" || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "cloak: usage: git cloak debug seed-remote --from <repo> [--key <ref>] <host-url>")
		return 2
	}
	url := strings.TrimPrefix(fs.Arg(0), "cloak::")

	key, err := keystore.Load(*ref)
	if err != nil {
		return printFail(stderr, err)
	}
	defer key.Wipe()
	lg, closeLog := logx.Setup(logx.Options{Stderr: stderr, StderrLevel: slog.LevelWarn, Role: "cli"})
	defer closeLog()
	g := gitx.New(lg)

	s := &seeder{g: g, lg: lg, key: key, url: url, branch: *branch}
	if err := s.run(*from, stdout); err != nil {
		return cliFail(stderr, err)
	}
	return 0
}

// seeder carries the shared context for a debug seed-remote operation - the
// git executor, logger, master key, and backend endpoint - so each seed
// phase hangs off it as a method taking only its own per-phase inputs,
// mirroring how Engine threads g/key through the push path.
type seeder struct {
	g      *gitx.G
	lg     *slog.Logger
	key    keystore.Key
	url    string
	branch string
}

func (s *seeder) run(from string, stdout io.Writer) error {
	fromGitDir, err := s.g.Out(gitx.Opts{Dir: from}, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return fmt.Errorf("resolve source repo: %w", err)
	}

	refs, wants, head, err := s.collectSeedRefs(fromGitDir)
	if err != nil {
		return err
	}

	// Scratch lives inside the source repo's git dir (same volume as the
	// user's data) rather than the system temp dir, so transient artifacts
	// never land on a separate, possibly non-encrypted volume.
	work, err := os.MkdirTemp(fromGitDir, "cloak-seed-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	pw, err := s.packSeedObjects(fromGitDir, work, wants)
	if err != nil {
		return err
	}

	m, manifestCT, err := s.buildSeedManifest(head, refs, pw)
	if err != nil {
		return err
	}

	if err := s.pushSeedCommit(work, m, manifestCT, pw); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Seeded %s (branch %s): generation 1, %d refs, pack %s (%d bytes)\n",
		s.url, s.branch, len(refs), pw.ID()[:12], pw.Size())
	return nil
}

// collectSeedRefs reads every head and tag from the source repository,
// returning the name->oid map, the deduplicated want oids, and the source
// HEAD symbolic ref. It errors if the source has no refs to seed.
func (s *seeder) collectSeedRefs(fromGitDir string) (refs map[string]string, wants []string, head string, err error) {
	refsOut, err := s.g.Out(gitx.Opts{GitDir: fromGitDir},
		"for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags")
	if err != nil {
		return nil, nil, "", fmt.Errorf("list source refs: %w", err)
	}
	refs = map[string]string{}
	for _, line := range strings.Split(refsOut, "\n") {
		oid, name, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found || oid == "" {
			continue
		}
		refs[name] = oid
		wants = append(wants, oid)
	}
	if len(refs) == 0 {
		return nil, nil, "", fmt.Errorf("source repository has no refs to seed")
	}
	head, _ = s.g.Out(gitx.Opts{GitDir: fromGitDir}, "symbolic-ref", "HEAD")
	return refs, wants, head, nil
}

// packSeedObjects packs the full history (all wants, no haves) into a fresh
// encrypting PackWriter under work, aborting the writer on failure.
func (s *seeder) packSeedObjects(fromGitDir, work string, wants []string) (*agecrypt.PackWriter, error) {
	pw, err := agecrypt.NewPackWriter(work, s.key)
	if err != nil {
		return nil, err
	}
	_, _, err = s.g.Run(gitx.Opts{GitDir: fromGitDir,
		Stdin:  strings.NewReader(strings.Join(wants, "\n") + "\n"),
		Stdout: pw},
		"pack-objects", "--revs", "--stdout", "--delta-base-offset")
	if err != nil {
		pw.Abort()
		return nil, fmt.Errorf("pack source objects: %w", err)
	}
	if err := pw.Close(); err != nil {
		return nil, err
	}
	return pw, nil
}

// buildSeedManifest mints a generation-1 manifest for the packed history and
// returns it alongside its encrypted ciphertext.
func (s *seeder) buildSeedManifest(head string, refs map[string]string, pw *agecrypt.PackWriter) (*manifest.Manifest, []byte, error) {
	m := manifest.New()
	repoID, err := manifest.NewRepoID()
	if err != nil {
		return nil, nil, err
	}
	m.RepoID = repoID
	m.Generation = 1
	m.Head = head
	m.Refs = refs
	m.Packs = []manifest.Pack{{ID: pw.ID(), Size: pw.Size()}}
	plain, err := manifest.Encode(m)
	if err != nil {
		return nil, nil, err
	}
	manifestCT, err := agecrypt.EncryptBytes(s.key, plain)
	if err != nil {
		return nil, nil, err
	}
	return m, manifestCT, nil
}

// pushSeedCommit hashes the manifest and pack into a backend at work, builds
// the seed commit, and fast-forward pushes it, rejecting a non-empty remote.
func (s *seeder) pushSeedCommit(work string, m *manifest.Manifest, manifestCT []byte, pw *agecrypt.PackWriter) error {
	be, err := backend.Open(s.g, filepath.Join(work, "backend.git"), s.url, s.branch, s.lg)
	if err != nil {
		return err
	}
	manifestOID, err := be.HashObject(bytes.NewReader(manifestCT))
	if err != nil {
		return err
	}
	packFile, err := os.Open(pw.Path())
	if err != nil {
		return err
	}
	packOID, err := be.HashObject(packFile)
	packFile.Close()
	if err != nil {
		return err
	}
	commit, err := be.BuildCommit("", manifestOID, map[string]string{pw.ID(): packOID}, m.Generation)
	if err != nil {
		return err
	}
	res, err := be.PushFF(commit)
	if err != nil {
		return err
	}
	if res != backend.PushOK {
		return fmt.Errorf("seed push rejected (remote not empty?)")
	}
	return nil
}
