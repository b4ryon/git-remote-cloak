// git-cloak debug seed-remote: builds a valid cloak backend branch on a
// host from a plain local repository, using the same backend write
// primitives the push path uses. Exists for milestone gates and the test
// harness (it lets the fetch path be developed and verified before the
// push path lands).
package cli

import (
	"bytes"
	"flag"
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
	fs := flag.NewFlagSet("debug seed-remote", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ref := fs.String("key", keystore.DefaultRef(), "key reference (file:<path>)")
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
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer key.Wipe()
	lg, closeLog := logx.Setup(logx.Options{Stderr: stderr, StderrLevel: slog.LevelWarn, Role: "cli"})
	defer closeLog()
	g := gitx.New(lg)

	if err := seedRemote(g, lg, key, *from, *branch, url, stdout); err != nil {
		msg := err.Error()
		if !strings.HasPrefix(msg, "cloak:") {
			msg = "cloak: " + msg
		}
		fmt.Fprintln(stderr, msg)
		return 1
	}
	return 0
}

func seedRemote(g *gitx.G, lg *slog.Logger, key keystore.Key, from, branch, url string, stdout io.Writer) error {
	fromGitDir, err := g.Out(gitx.Opts{Dir: from}, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return fmt.Errorf("resolve source repo: %w", err)
	}

	refsOut, err := g.Out(gitx.Opts{GitDir: fromGitDir},
		"for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags")
	if err != nil {
		return fmt.Errorf("list source refs: %w", err)
	}
	refs := map[string]string{}
	var wants []string
	for _, line := range strings.Split(refsOut, "\n") {
		oid, name, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found || oid == "" {
			continue
		}
		refs[name] = oid
		wants = append(wants, oid)
	}
	if len(refs) == 0 {
		return fmt.Errorf("source repository has no refs to seed")
	}
	head, _ := g.Out(gitx.Opts{GitDir: fromGitDir}, "symbolic-ref", "HEAD")

	// Scratch lives inside the source repo's git dir (same volume as the
	// user's data) rather than the system temp dir, so transient artifacts
	// never land on a separate, possibly non-encrypted volume.
	work, err := os.MkdirTemp(fromGitDir, "cloak-seed-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	// Pack the full history (all wants, no haves), encrypting as it streams.
	pw, err := agecrypt.NewPackWriter(work, key)
	if err != nil {
		return err
	}
	_, _, err = g.Run(gitx.Opts{GitDir: fromGitDir,
		Stdin:  strings.NewReader(strings.Join(wants, "\n") + "\n"),
		Stdout: pw},
		"pack-objects", "--revs", "--stdout", "--delta-base-offset")
	if err != nil {
		pw.Abort()
		return fmt.Errorf("pack source objects: %w", err)
	}
	if err := pw.Close(); err != nil {
		return err
	}

	m := manifest.New()
	repoID, err := manifest.NewRepoID()
	if err != nil {
		return err
	}
	m.RepoID = repoID
	m.Generation = 1
	m.Head = head
	m.Refs = refs
	m.Packs = []manifest.Pack{{ID: pw.ID(), Size: pw.Size()}}
	plain, err := manifest.Encode(m)
	if err != nil {
		return err
	}
	manifestCT, err := agecrypt.EncryptBytes(key, plain)
	if err != nil {
		return err
	}

	be, err := backend.Open(g, filepath.Join(work, "backend.git"), url, branch, lg)
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
	fmt.Fprintf(stdout, "Seeded %s (branch %s): generation 1, %d refs, pack %s (%d bytes)\n",
		url, branch, len(refs), pw.ID()[:12], pw.Size())
	return nil
}
