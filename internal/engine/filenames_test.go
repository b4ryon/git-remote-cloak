// Filename robustness: names that can appear in a notes vault (Unicode in
// both normalization forms, CJK, Cyrillic, emoji, spaces, tabs, quotes,
// backslashes, leading dashes, newlines, long names) must survive the
// encrypt-push-fetch-checkout round trip byte-for-byte. Cloak never parses
// user filenames (they live inside opaque pack data), so the engine must
// be transparent to all of them. The one sanctioned normalization is
// git's own core.precomposeunicode on macOS: NFD input from the
// filesystem is stored NFC in the tree, which is what makes two Macs
// converge on a single form instead of accumulating duplicates. Both
// normalization forms and the expected git behavior are derived with
// golang.org/x/text/unicode/norm rather than hand-built byte sequences.
package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// nfdName is written to disk with a combining acute accent (NFD); git with
// core.precomposeunicode stores it precomposed (NFC) on darwin.
var nfdName = norm.NFD.String("noté-decomposed.md")

// trickyFiles maps on-disk name -> content. Every name must round trip.
func trickyFiles() map[string]string {
	return map[string]string{
		"simple.txt":                      "plain ascii",
		"with space.md":                   "space in name",
		"tab\tchar.txt":                   "tab in name",
		"quote\"double.txt":               "double quote",
		"quote'single.txt":                "single quote",
		"back\\slash.txt":                 "backslash",
		"-leading-dash.txt":               "dash first",
		".hidden":                         "dotfile",
		"trailing.dot.":                   "trailing dot",
		"colon:name.txt":                  "colon",
		"umläut-öü.txt":                   "nfc umlauts",
		nfdName:                           "nfd decomposed accent",
		"笔记.md":                           "cjk name",
		"заметки.txt":                     "cyrillic name",
		"\U0001F4DD-note.md":              "emoji name",
		"new\nline.txt":                   "newline in name",
		strings.Repeat("a", 200) + ".txt": "200-char name",
	}
}

// expectedTreeName maps an on-disk name to the name git stores in the
// tree: on darwin core.precomposeunicode precomposes every filename to
// NFC; elsewhere names are stored byte-for-byte.
func expectedTreeName(name string) string {
	if runtime.GOOS == "darwin" {
		return norm.NFC.String(name)
	}
	return name
}

func TestEngineFilenameRoundTrip(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if nfdName == norm.NFC.String(nfdName) {
		t.Fatal("nfd test name has no decomposable rune; the normalization case would be vacuous")
	}
	a := newMachine(t, g, host, key)
	b := newMachine(t, g, host, key)
	for _, m := range []*machine{a, b} {
		// Deterministic across git builds: enable the macOS NFD->NFC
		// precomposition explicitly (git init usually sets it on darwin).
		if _, _, err := g.Run(gitx.Opts{GitDir: m.gitDir}, "config", "core.precomposeunicode", "true"); err != nil {
			t.Fatal(err)
		}
	}

	files := trickyFiles()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(a.dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
	}
	if _, _, err := g.Run(gitx.Opts{Dir: a.dir, Scrub: true}, "add", "-A"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{Dir: a.dir, Scrub: true}, "commit", "-q", "-m", "tricky names"); err != nil {
		t.Fatal(err)
	}
	oid, err := g.Out(gitx.Opts{Dir: a.dir}, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}

	results, _ := a.push(t, a.load(t), RefUpdate{Src: mainRef, Dst: mainRef})
	if results[0].Err != "" {
		t.Fatalf("push rejected: %s", results[0].Err)
	}

	rsB := b.load(t)
	if _, err := b.e.FetchApply(rsB); err != nil {
		t.Fatal(err)
	}
	if !b.e.HaveObject(oid) {
		t.Fatal("commit with tricky filenames did not arrive")
	}

	// The tree on B must hold exactly the expected (post-precompose) names.
	out, _, err2 := b.g.Run(gitx.Opts{GitDir: b.gitDir}, "ls-tree", "-r", "--name-only", "-z", oid)
	if err2 != nil {
		t.Fatal(err2)
	}
	var got []string
	for _, n := range strings.Split(out, "\x00") {
		if n != "" {
			got = append(got, n)
		}
	}
	var want []string
	for name := range files {
		want = append(want, expectedTreeName(name))
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("tree has %d entries, want %d:\ngot  %q\nwant %q", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tree entry %d = %q, want %q", i, got[i], want[i])
		}
	}

	// Materialize on B and verify contents land readable on disk.
	if _, _, err := g.Run(gitx.Opts{GitDir: b.gitDir}, "update-ref", "refs/heads/main", oid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{Dir: b.dir, Scrub: true}, "checkout", "-f", "main"); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		onDisk := expectedTreeName(name)
		gotContent, err := os.ReadFile(filepath.Join(b.dir, onDisk))
		if err != nil {
			t.Errorf("checkout missing %q: %v", onDisk, err)
			continue
		}
		if string(gotContent) != content {
			t.Errorf("%q content = %q, want %q", onDisk, gotContent, content)
		}
	}
}

// TestEngineUnicodeRefRoundTrip pins that non-ASCII branch names pass the
// manifest validation and the full push/list cycle (the helper protocol is
// byte-oriented; only "refs/" prefixed names are required).
func TestEngineUnicodeRefRoundTrip(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, _ := keystore.Generate()

	a := newMachine(t, g, host, key)
	oid := a.commit(t, "f.txt", "content")
	uniRef := "refs/heads/notes-笔记"
	results, rs := a.push(t, a.load(t),
		RefUpdate{Src: mainRef, Dst: mainRef},
		RefUpdate{Src: mainRef, Dst: uniRef})
	for _, r := range results {
		if r.Err != "" {
			t.Fatalf("push of %q rejected: %s", r.Dst, r.Err)
		}
	}
	if rs.Manifest.Refs[uniRef] != oid {
		t.Fatalf("unicode ref not in manifest: %v", rs.Manifest.Refs)
	}

	b := newMachine(t, g, host, key)
	rsB := b.load(t)
	if rsB.Manifest.Refs[uniRef] != oid {
		t.Fatalf("b does not see the unicode ref: %v", rsB.Manifest.Refs)
	}
	if got := HeadForList(rsB.Manifest); got != mainRef {
		t.Fatalf("HeadForList = %q, want %s", got, mainRef)
	}
}
