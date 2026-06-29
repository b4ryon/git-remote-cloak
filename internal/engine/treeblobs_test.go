// Regression test for the push-time pack-tree completeness check: treePackBlobs
// must refuse to assemble a commit tree that omits a blob for a pack the
// manifest declares live, rather than publishing a manifest that references a
// pack with no backing blob (which would only surface later as a fetch failure
// on every client).
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

func TestTreePackBlobsRefusesMissingLivePackBlob(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newMachine(t, g, host, key).e

	// A manifest declaring one live pack, against a blobSource that carries no
	// pack blobs (blobSource "" -> PackBlobOIDs returns an empty map). With no
	// new pack to add either, the live pack has no blob in the assembled tree.
	man := &manifest.Manifest{Packs: []manifest.Pack{{ID: strings.Repeat("a", 64), Size: 1}}}
	if _, err := e.treePackBlobs(commitInput{man: man, blobSource: ""}); err == nil {
		t.Fatal("treePackBlobs accepted a live manifest pack with no backing blob")
	} else if !strings.Contains(err.Error(), "no blob for it") {
		t.Fatalf("unexpected error (want missing-blob refusal): %v", err)
	}

	// Control: a manifest-only push (no live packs) must still assemble cleanly.
	if _, err := e.treePackBlobs(commitInput{man: &manifest.Manifest{}, blobSource: ""}); err != nil {
		t.Fatalf("manifest-only tree assembly should succeed, got: %v", err)
	}
}

// TestTreePackBlobsVerifiesReusedBlobCiphertext is the CR-001 regression: the
// push path reuses pack blobs from the host's current backend tree by OID; a
// host that swapped a blob's content under the same manifest pack id must not be
// laundered into a freshly signed commit. treePackBlobs must re-hash each reused
// blob and refuse when the ciphertext no longer matches its pack id.
func TestTreePackBlobsVerifiesReusedBlobCiphertext(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newMachine(t, g, host, key).e

	manifestOID, err := e.Be.HashObject(strings.NewReader("manifest-ciphertext"))
	if err != nil {
		t.Fatal(err)
	}

	// packID is what the manifest declares; the stored blob's content does NOT
	// hash to it (the host tampered with the pack blob under the same filename).
	packID := strings.Repeat("a", 64)
	corruptOID, err := e.Be.HashObject(strings.NewReader("tampered-ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	src, err := e.Be.BuildCommit("", manifestOID, map[string]string{packID: corruptOID}, 1)
	if err != nil {
		t.Fatal(err)
	}

	man := &manifest.Manifest{Packs: []manifest.Pack{{ID: packID, Size: 1}}}
	_, err = e.treePackBlobs(commitInput{man: man, blobSource: src})
	if err == nil {
		t.Fatal("treePackBlobs reused a corrupted pack blob without verifying it")
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Tamper {
		t.Fatalf("reused-blob mismatch not classified Tamper: %v", err)
	}
	if !strings.Contains(err.Error(), "does not match manifest id") {
		t.Fatalf("error lacks ciphertext-mismatch detail: %v", err)
	}

	// Control: an honestly-stored reused blob (content hashes to its id) passes.
	good := []byte("honest-ciphertext")
	goodID := hex.EncodeToString(sha256Sum(good))
	goodOID, err := e.Be.HashObject(strings.NewReader(string(good)))
	if err != nil {
		t.Fatal(err)
	}
	src2, err := e.Be.BuildCommit("", manifestOID, map[string]string{goodID: goodOID}, 1)
	if err != nil {
		t.Fatal(err)
	}
	man2 := &manifest.Manifest{Packs: []manifest.Pack{{ID: goodID, Size: int64(len(good))}}}
	if _, err := e.treePackBlobs(commitInput{man: man2, blobSource: src2}); err != nil {
		t.Fatalf("treePackBlobs rejected an honestly-stored reused blob: %v", err)
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
