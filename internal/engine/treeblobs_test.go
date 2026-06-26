// Regression test for the push-time pack-tree completeness check: treePackBlobs
// must refuse to assemble a commit tree that omits a blob for a pack the
// manifest declares live, rather than publishing a manifest that references a
// pack with no backing blob (which would only surface later as a fetch failure
// on every client).
package engine

import (
	"strings"
	"testing"

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
