// Unit tests for the repository-identity pin: round-trip persistence and the
// trust-on-first-use / match / mismatch decisions of CheckRepoID.
package state

import (
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

func TestRepoIDPinRoundTrip(t *testing.T) {
	d, err := Open(t.TempDir(), "origin", "u")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := d.LoadRepoID(); err != nil || ok {
		t.Fatalf("fresh dir reports a repo-id pin: ok=%v err=%v", ok, err)
	}
	const id = "0123456789abcdef0123456789abcdef"
	if err := d.SaveRepoID(id); err != nil {
		t.Fatal(err)
	}
	got, ok, err := d.LoadRepoID()
	if err != nil || !ok || got != id {
		t.Fatalf("round trip: id=%q ok=%v err=%v", got, ok, err)
	}
	if err := d.ClearRepoID(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.LoadRepoID(); ok {
		t.Fatal("pin survived ClearRepoID")
	}
}

func TestCheckRepoIDDecisions(t *testing.T) {
	d, err := Open(t.TempDir(), "origin", "u")
	if err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{RepoID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

	// Empty remote carries no manifest: nothing to check.
	if err := d.CheckRepoID(nil); err != nil {
		t.Fatalf("empty remote rejected: %v", err)
	}
	// First contact (no local pin): trust-on-first-use accept, and CheckRepoID
	// must NOT persist a pin (CommitPin does that after a verified apply).
	if err := d.CheckRepoID(m); err != nil {
		t.Fatalf("TOFU rejected: %v", err)
	}
	if _, ok, _ := d.LoadRepoID(); ok {
		t.Fatal("CheckRepoID persisted a pin on first contact")
	}
	// Once pinned, a matching id passes.
	if err := d.SaveRepoID(m.RepoID); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckRepoID(m); err != nil {
		t.Fatalf("matching repo id rejected: %v", err)
	}
	// A different id is a tamper alarm (cross-repo substitution).
	other := &manifest.Manifest{RepoID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	err = d.CheckRepoID(other)
	if err == nil {
		t.Fatal("changed repo id accepted")
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Tamper {
		t.Fatalf("repo-id mismatch classified %v, want Tamper", kind)
	}
}
