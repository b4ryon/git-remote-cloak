// Host and Client fixtures for the integration and security suites: a Host
// is a hermetic local bare repository acting as the git host; a Client is a
// plain repository with an isolated environment (own HOME, global git
// config, PATH-injected cloak binaries, shared test master key) that runs
// real git against the host through the cloak:: remote helper.
package harness

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// MustBinDir returns the directory holding the compiled helper binaries.
func MustBinDir(t *testing.T) string {
	t.Helper()
	dir, err := EnsureBuilt()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// NewKeyFile generates a fresh test master key file and returns its path.
func NewKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master.key")
	cmd := exec.Command(filepath.Join(MustBinDir(t), "git-cloak"), "keygen", "--key", "file:"+path) // #nosec G204 -- test harness: fixed binary, test-controlled args
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	return path
}

// Host is a hermetic local bare repository acting as the git host.
type Host struct {
	T   *testing.T
	Dir string
}

// NewHost creates the bare host repo with partial-fetch support enabled
// (GitHub supports it; the harness host should too).
func NewHost(t *testing.T) *Host {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "host.git")
	h := &Host{T: t, Dir: dir}
	if out, err := exec.Command("git", "init", "--bare", "--initial-branch", "cloak", dir).CombinedOutput(); err != nil { // #nosec G204 -- test harness: fixed binary, test-controlled args
		t.Fatalf("init host: %v\n%s", err, out)
	}
	h.Git("config", "uploadpack.allowfilter", "true")
	return h
}

// Git runs git against the host repo, failing the test on error.
func (h *Host) Git(args ...string) string {
	h.T.Helper()
	cmd := exec.Command("git", append([]string{"--git-dir", h.Dir}, args...)...) // #nosec G204 -- test harness: fixed binary, test-controlled args
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.T.Fatalf("host git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// InstallPreReceive writes an executable pre-receive hook on the host.
func (h *Host) InstallPreReceive(script string) {
	h.T.Helper()
	hooks := filepath.Join(h.Dir, "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil { // #nosec G301 -- test fixture dir; ephemeral t.TempDir() tree
		h.T.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, "pre-receive"), []byte(script), 0o755); err != nil { // #nosec G306 -- test fixture: git hook must be executable
		h.T.Fatal(err)
	}
}

// RemovePreReceive deletes the pre-receive hook.
func (h *Host) RemovePreReceive() {
	h.T.Helper()
	_ = os.Remove(filepath.Join(h.Dir, "hooks", "pre-receive"))
}

// GitRaw runs git against the host and returns stdout WITHOUT trimming
// (binary-safe; needed for cat-file blob).
func (h *Host) GitRaw(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"--git-dir", h.Dir}, args...)...) // #nosec G204 -- test harness: fixed binary, test-controlled args
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("host git %v: %v\n%s", args, err, errb.String())
	}
	return out.String()
}

// HashObjectStdin writes data as a blob into the host object store and
// returns its oid.
func (h *Host) HashObjectStdin(t *testing.T, data []byte) string {
	t.Helper()
	cmd := exec.Command("git", "--git-dir", h.Dir, "hash-object", "-w", "--stdin") // #nosec G204 -- test harness: fixed binary, test-controlled args
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("host hash-object: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// ReplaceTreeEntry rewrites branch's tip into a tampered commit that is
// identical except the blob at path now points at newBlobOID. The new
// commit keeps the original's parent, author/committer identity, and dates,
// so only ciphertext changes (chain position and generation are untouched).
func (h *Host) ReplaceTreeEntry(t *testing.T, branch, path, newBlobOID string) {
	t.Helper()
	tip := h.Git("rev-parse", branch)
	// Read the full recursive tree, swap the target entry, rebuild trees.
	lsOut := h.Git("ls-tree", "-r", tip)
	newTree := h.mktreeRecursive(t, rewriteTreeFlat(t, lsOut, path, newBlobOID))
	parents := strings.Fields(h.Git("rev-list", "--parents", "-n", "1", tip))
	commitArgs := []string{"commit-tree", newTree, "-m", "cloak"}
	for _, p := range parents[1:] {
		commitArgs = append(commitArgs, "-p", p)
	}
	authInfo := h.Git("log", "-1", "--format=%an|%ae|%ad", "--date=raw", tip)
	parts := strings.Split(authInfo, "|")
	env := []string{
		"GIT_AUTHOR_NAME=" + parts[0], "GIT_AUTHOR_EMAIL=" + parts[1], "GIT_AUTHOR_DATE=" + parts[2],
		"GIT_COMMITTER_NAME=" + parts[0], "GIT_COMMITTER_EMAIL=" + parts[1], "GIT_COMMITTER_DATE=" + parts[2],
	}
	cmd := exec.Command("git", append([]string{"--git-dir", h.Dir}, commitArgs...)...) // #nosec G204 -- test harness: fixed binary, test-controlled args
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("host commit-tree: %v", err)
	}
	h.Git("update-ref", "refs/heads/"+branch, strings.TrimSpace(string(out)))
}

// rewriteTreeFlat parses recursive ls-tree output and returns flat
// "mode type oid\tpath" lines with the entry at path repointed to newBlobOID.
func rewriteTreeFlat(t *testing.T, lsOut, path, newBlobOID string) string {
	t.Helper()
	var b strings.Builder
	for _, line := range strings.Split(lsOut, "\n") {
		meta, name, found := strings.Cut(line, "\t")
		if !found {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) != 3 {
			t.Fatalf("unexpected ls-tree line: %q", line)
		}
		mode, typ, oid := fields[0], fields[1], fields[2]
		if name == path {
			oid = newBlobOID
		}
		fmt.Fprintf(&b, "%s %s %s\t%s\n", mode, typ, oid, name)
	}
	return b.String()
}

// mktreeRecursive builds nested trees from flat "mode type oid\tpath" lines
// using git mktree --batch-style emulation via a temporary index.
func (h *Host) mktreeRecursive(t *testing.T, flat string) string {
	t.Helper()
	idx := filepath.Join(h.T.TempDir(), "tamper.index")
	for _, line := range strings.Split(strings.TrimSpace(flat), "\n") {
		meta, name, _ := strings.Cut(line, "\t")
		fields := strings.Fields(meta)
		cmd := exec.Command("git", "--git-dir", h.Dir, "update-index", "--add", // #nosec G204 -- test harness: fixed binary, test-controlled args
			"--cacheinfo", fields[0]+","+fields[2]+","+name)
		cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+idx)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("update-index: %v\n%s", err, out)
		}
	}
	cmd := exec.Command("git", "--git-dir", h.Dir, "write-tree") // #nosec G204 -- test harness: fixed binary, test-controlled args
	cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+idx)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("write-tree: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// LsTreeR lists all paths in the branch tip's tree.
func (h *Host) LsTreeR(branch string) []string {
	h.T.Helper()
	out := h.Git("ls-tree", "-r", "--name-only", branch)
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

// Client is an isolated git client wired up for cloak:: remotes.
type Client struct {
	T    *testing.T
	Base string
	Dir  string
	Env  []string
	bin  string
}

// NewClient builds the isolated environment: own HOME and global git
// config (identity, default branch, cloak.keyRef), cloak binaries first in
// PATH, debug logging on.
func NewClient(t *testing.T, name, keyFile string) *Client {
	t.Helper()
	bin := MustBinDir(t)
	base := filepath.Join(t.TempDir(), name)
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(home, "gitconfig")
	// gc.auto=0 disables git's automatic `gc --auto`, which on Linux detaches
	// into the background (gc.autoDetach) and can keep writing to
	// .git/objects/pack after the foreground porcelain (clone/fetch/pull)
	// returns. That races t.TempDir()'s RemoveAll and fails cleanup with
	// "directory not empty" (a flake seen on the Linux CI runner, not darwin).
	cfg := "[user]\n\tname = cloak-test\n\temail = test@cloak.invalid\n" +
		"[init]\n\tdefaultBranch = main\n" +
		"[gc]\n\tauto = 0\n\tautoDetach = false\n" +
		"[cloak]\n\tkeyRef = file:" + keyFile + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"GIT_CONFIG_GLOBAL=" + cfgPath,
		"GIT_CONFIG_NOSYSTEM=1",
		"TMPDIR=" + os.TempDir(),
		"CLOAK_LOG=debug",
		"LC_ALL=C",
	}
	return &Client{T: t, Base: base, Dir: filepath.Join(base, "repo"), Env: env, bin: bin}
}

// runEnv runs name with the given environment, working inside the repo when it
// exists (else the base dir), and returns captured stdout, stderr, and error.
func (c *Client) runEnv(env []string, name string, args ...string) (string, string, error) {
	cmd := exec.Command(name, args...) // #nosec G204 -- test harness: fixed binary, test-controlled args
	if _, err := os.Stat(c.Dir); err == nil {
		cmd.Dir = c.Dir
	} else {
		cmd.Dir = c.Base
	}
	cmd.Env = env
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

func (c *Client) run(name string, args ...string) (string, string, error) {
	return c.runEnv(c.Env, name, args...)
}

// Git runs git in the client environment (inside the repo when it exists).
func (c *Client) Git(args ...string) (string, string, error) { return c.run("git", args...) }

// GitEnv runs git with extra environment variables appended (e.g. the
// CLOAK_TEST_HOLD_BEFORE_PUSH synchronization hook).
func (c *Client) GitEnv(extra []string, args ...string) (string, string, error) {
	return c.runEnv(append(append([]string{}, c.Env...), extra...), "git", args...)
}

// mustRun runs the given command runner (Git or Cloak) and fails the test with a
// labeled command trace on error, otherwise returns the trimmed stdout. It owns
// the shared check/trace/trim tail of MustGit/MustCloak so the failure-trace
// format lives in one place. Callers keep their own c.T.Helper() so the reported
// failure line stays the test's call site, not this delegation.
func (c *Client) mustRun(label string, run func(...string) (string, string, error), args ...string) string {
	c.T.Helper()
	out, errb, err := run(args...)
	if err != nil {
		c.T.Fatalf("%s %v: %v\nstdout: %s\nstderr: %s", label, args, err, out, errb)
	}
	return strings.TrimSpace(out)
}

// MustGit runs git and fails the test on error.
func (c *Client) MustGit(args ...string) string {
	c.T.Helper()
	return c.mustRun("git", c.Git, args...)
}

// Cloak runs the git-cloak operator binary in the client environment.
func (c *Client) Cloak(args ...string) (string, string, error) {
	return c.run(filepath.Join(c.bin, "git-cloak"), args...)
}

// CloakStdin runs git-cloak feeding s on stdin, returning text stdout.
func (c *Client) CloakStdin(s string, args ...string) (string, string, error) {
	out, errb, err := c.CloakStdinBytes(s, args...)
	return string(out), errb, err
}

// CloakStdinBytes runs git-cloak feeding s on stdin, returning raw stdout
// bytes (binary-safe; needed for ciphertext output).
func (c *Client) CloakStdinBytes(s string, args ...string) ([]byte, string, error) {
	cmd := exec.Command(filepath.Join(c.bin, "git-cloak"), args...) // #nosec G204 -- test harness: fixed binary, test-controlled args
	cmd.Dir = c.Base
	cmd.Env = c.Env
	cmd.Stdin = strings.NewReader(s)
	var out bytes.Buffer
	var errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.Bytes(), errb.String(), err
}

// MustCloak runs git-cloak and fails the test on error.
func (c *Client) MustCloak(args ...string) string {
	c.T.Helper()
	return c.mustRun("git-cloak", c.Cloak, args...)
}

// InstallGitShim places a `git` wrapper first on the client's PATH that
// appends every invocation's arguments to a log file then execs the real
// git. Used to prove the helper never issues a plain --force. Returns the
// log file path. The shim is added to a dedicated dir placed before the
// cloak bin dir, so the helper's own git subprocesses are intercepted.
func (c *Client) InstallGitShim(t *testing.T) string {
	t.Helper()
	shimDir := filepath.Join(c.Base, "shim")
	if err := os.MkdirAll(shimDir, 0o755); err != nil { // #nosec G301 -- test fixture dir; ephemeral t.TempDir() tree
		t.Fatal(err)
	}
	logPath := filepath.Join(c.Base, "git-invocations.log")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + logPath + "\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "git"), []byte(script), 0o755); err != nil { // #nosec G306 -- test fixture: git shim must be executable
		t.Fatal(err)
	}
	for i, kv := range c.Env {
		if strings.HasPrefix(kv, "PATH=") {
			c.Env[i] = "PATH=" + shimDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}
	return logPath
}

// InitRepo creates the client's working repository.
func (c *Client) InitRepo() {
	c.T.Helper()
	c.MustGit("init", c.Dir)
}

// MustClone clones cloak::<url> into the client's repo dir.
func (c *Client) MustClone(url string) {
	c.T.Helper()
	out, errb, err := c.Git("clone", "cloak::"+url, c.Dir)
	if err != nil {
		c.T.Fatalf("clone: %v\nstdout: %s\nstderr: %s", err, out, errb)
	}
}

// AddOrigin adds a cloak::<url> origin remote to the client's repo. It owns
// the cloak:: scheme for the push-side setup the suites repeat before their
// first push, the symmetric counterpart of MustClone on the fetch side.
func (c *Client) AddOrigin(url string) {
	c.T.Helper()
	c.MustGit("remote", "add", "origin", "cloak::"+url)
}

// WriteFile writes content under the repo working tree.
func (c *Client) WriteFile(rel, content string) {
	c.T.Helper()
	path := filepath.Join(c.Dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- test fixture dir; ephemeral t.TempDir() tree
		c.T.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { // #nosec G306 -- test fixture: ephemeral working-tree file
		c.T.Fatal(err)
	}
}

// Commit stages everything and commits.
func (c *Client) Commit(msg string) {
	c.T.Helper()
	c.MustGit("add", "-A")
	c.MustGit("commit", "-m", msg)
}

// HeadOID returns the current HEAD object id.
func (c *Client) HeadOID() string {
	c.T.Helper()
	return c.MustGit("rev-parse", "HEAD")
}

// DebugLog returns the helper's per-remote debug log contents (all remotes).
func (c *Client) DebugLog() string {
	c.T.Helper()
	var sb strings.Builder
	root := filepath.Join(c.Dir, ".git", "cloak")
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && filepath.Base(path) == "log" {
			b, rerr := os.ReadFile(path) // #nosec G304 G122 -- test-only walk reading the client's own ephemeral .git/cloak logs
			if rerr == nil {
				fmt.Fprintf(&sb, "==> %s\n%s\n", path, b)
			}
		}
		return nil
	})
	return sb.String()
}
