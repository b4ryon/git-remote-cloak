// Fuzz tests for engine logic that the remote-helper protocol path depends on
// but that needs no git host. HeadForList resolves the single HEAD symref the
// helper advertises on "list" (helper.go: "@<head> HEAD"); git checks that ref
// out on clone, so a wrong choice -- above all one that names a ref the
// manifest does not actually carry -- silently lands the user on the wrong
// branch or a dangling HEAD. The existing unit test pins seven fixed cases;
// this generalizes the full selection contract over arbitrary ref sets and head
// values, which only ever reach list as a Decode/Validate-accepted manifest in
// production. packHeadSniffer is the other host-data consumer fuzzed here: it
// reads the object count out of git pack-objects' 12-byte PACK header while
// streaming the pack through to the encryptor, and that count decides whether
// the push keeps or drops the pack as empty (push.go: "if bp.count > 0"), so a
// chunk-boundary reassembly error would silently discard a real pack or publish
// an empty one. packSkippable/replacesCovered are the fetch/apply-path skip
// gate: for each manifest pack, packSkippable decides whether it can be marked
// applied WITHOUT downloading it (every pack it replaces is already applied, or
// the local repo already holds the full object closure). Skipping a pack that
// actually delivers new objects silently corrupts the fetch, so the gate's
// "skip only when nothing new is owed" contract over the host-controlled
// Pack.Replaces field is correctness-critical. revListReportsMissing is the
// other half of that closure verdict: FuzzPackSkippable fuzzes closure() as an
// abstract bool, while revListReportsMissing is the actual parser of git
// rev-list --objects --missing=print output that produces it. HasObjectClosure
// reports a complete closure only when that parser finds NO missing-object
// ("?"-prefixed) line, so a parse that under-reports a "?" line would let
// downloadUnlessSkippable skip a pack the local repo is in fact missing objects
// for -- a fail-safe whose parse correctness is correctness-critical.
// keepFileFromIndexPack is the last parser on the apply path: after a pack is
// verified, decrypted and fed to git index-pack, it reads the "keep\t<hash>"
// line index-pack prints and builds the .keep lock-file path. That path is
// returned verbatim to git as the fetch "lock" line (helper.go handleFetch);
// the .keep file is what stops git from garbage-collecting the just-applied
// pack, so a mis-parse (a dropped lock or a wrong/escaping path) would let git
// reclaim a pack the fetch just delivered or report a bogus lock to git.
// planRefUpdates is the push-side projection consumer fuzzed here over its pure
// DELETE path: it folds a batch of "push :dst" delete refspecs against the
// remote ref set into per-ref accept/reject results and the next manifest's ref
// set, never running git (a delete refspec is decideRef's one host-free branch),
// so the deletion-authorization gate ("remote ref does not exist" vs. removing
// the ref) and the no-input-mutation contract preparePush relies on (it hands in
// the live manifest.Refs map) are pinned without a host.
// repackManifest is the FullRepack manifest builder fuzzed here: a full repack
// squashes every live pack into one merged pack, and the next-generation
// manifest must bump the rollback generation by exactly one, list that single
// pack, and carry EVERY prior pack id in its Replaces list (so clients that
// already applied the old packs skip the merged one -- packSkippable), while
// carrying the repo identity/head/refs/version forward unchanged and not
// mutating the caller's current manifest. repackOnce never Validates this
// manifest before persisting man.Generation/man.Packs[0].ID, so the
// construction contract is self-enforced.
// nextPushManifest is the NORMAL-push manifest builder fuzzed here, the common
// counterpart to repackManifest: assembleManifest resolves the random repo id
// and the git HEAD symref, then delegates the pure construction to it. It bumps
// the generation by exactly one, installs the new ref set and head, and appends
// the new pack while RETAINING every pack base already carried (a push adds a
// pack, it never drops a live one, or clients lose access to those objects).
// assembleManifest does Validate the result, but Validate enforces neither the
// exactly-one generation bump nor the retain-all-prior-packs continuity, so a
// builder that mis-bumped or silently dropped a pack would still pass Validate --
// these invariants need a direct pin.
// selectManifestHead is the push/WRITE-side head selector fuzzed here, the
// counterpart to FuzzHeadForList's read/list side: when assembling the next
// manifest, it picks the head to PUBLISH (the local HEAD branch if among the
// refs, else the previous head if still among them, else empty) from the one
// git query headForManifest resolves (the local HEAD symref). Its load-bearing
// safety invariant is membership: the published head must always be "" or a ref
// the manifest actually carries, since HeadForList later advertises it and a
// stored head naming a missing ref would land a clone on a dangling HEAD.
// fastForwardExempt is the last pure decision on the push-authorization path,
// lifted out of nonFastForwardReason: it decides whether an update may be
// accepted WITHOUT the git ancestry (merge-base) check -- a ref new on the
// remote, a forced push, or a no-op (tip unchanged) is exempt. Its load-bearing
// security invariant is the converse: a non-force push that changes an EXISTING
// ref's tip is NEVER exempt, so it must fall through to the ancestry test;
// exempting it would let a silent non-fast-forward history rewrite be accepted
// without verification. The git-backed branches of nonFastForwardReason
// (HaveObject, merge-base) need a host and stay covered by the integration suite.
// retainLivePackBlobs is the commit-building blob-reuse filter fuzzed here,
// lifted out of treePackBlobs: when assembling the next backend commit, cloak
// reuses the existing commit's pack blobs (parsed from the HOST-controlled
// backend tree via PackBlobOIDs) instead of re-uploading them, but only for
// pack ids the new manifest still declares live (manifest.PackIDs()). Its
// load-bearing invariant is that a blob for a non-live id -- a superseded pack
// or anything the host injected into its tree -- can never survive into the
// published tree; this target also exercises manifest.PackIDs(), the one
// manifest read-side consumer left without a direct fuzz.
// consolidatedPacks is the geometric-consolidation pack-set builder fuzzed here,
// lifted out of applyConsolidation. It is the third distinct manifest pack-set
// construction contract alongside repackManifest (replace ALL packs with one
// merged pack) and nextPushManifest (append a pack, retain ALL prior): a
// consolidation drops only the VICTIM subset, retains the non-victim survivors,
// and appends one merged pack carrying every victim id as Replaces. The
// load-bearing invariant ties to packSkippable: every live pack must end up
// either retained as a survivor or declared superseded in the merged pack's
// Replaces, or a client that had not yet applied a dropped pack would never
// re-download it. applyConsolidation does Validate the result, but Validate sees
// neither "victims are exactly the dropped packs" nor "Replaces lists them all",
// so this construction contract needs a direct pin.
// canMarkConsolidated is the consolidation's mark-applied gate fuzzed here,
// lifted out of indexVictims. It is the WRITE-side mirror of packSkippable's
// applied-set machinery (iter 29): after merging the victim packs into one, it
// decides whether that merged pack may be recorded as already applied -- true
// only when every victim is either the not-yet-pushed pack (its objects were
// just packed from the local repo) or was already applied locally. The
// load-bearing one-sided floor is that canMark is true ONLY when every victim's
// objects are guaranteed local: a wrong true would record the merged pack as
// applied while the local repo lacks a never-applied victim's objects, so a
// future fetch would skip downloading it (packSkippable treats an applied pack
// as covered) and those objects would stay missing forever (the applied set is
// never re-examined). The per-victim scratch indexing stays in indexVictims, so
// the gate is fuzz-reachable without a git host.
package engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

// FuzzHeadForList pins HeadForList's HEAD-symref selection contract. It builds a
// manifest from a fuzzed head plus a newline-separated ref set, keeps only
// manifests Validate accepts (mirroring that list never sees an unvalidated
// manifest), and asserts the structural safety invariants together with the
// documented priority order (manifest head > main > master > first branch
// alphabetically). The membership invariant is the load-bearing one: the
// advertised HEAD must always name a ref the manifest actually holds, never an
// invented one.
func FuzzHeadForList(f *testing.F) {
	const (
		repoID = "0123456789abcdef0123456789abcdef"
		oid    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	// Seeds covering every branch of the selection: head wins, dangling head
	// falls through, main beats master, master beats the rest, alphabetical
	// fallback, and a branchless (tags-only / empty) manifest.
	f.Add("refs/heads/dev", "refs/heads/dev\nrefs/heads/main")
	f.Add("refs/heads/gone", "refs/heads/main\nrefs/heads/master")
	f.Add("", "refs/heads/zz\nrefs/heads/main\nrefs/heads/master")
	f.Add("", "refs/heads/zz\nrefs/heads/master")
	f.Add("", "refs/heads/zeta\nrefs/heads/alpha")
	f.Add("", "refs/tags/v1")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, head, refsBlob string) {
		m := &manifest.Manifest{
			Version: manifest.Version,
			RepoID:  repoID,
			Head:    head,
			Refs:    map[string]string{},
		}
		for _, name := range strings.Split(refsBlob, "\n") {
			if name != "" {
				m.Refs[name] = oid
			}
		}
		// Production advertises only a manifest Decode/Validate accepted; an
		// unvalidated head could be a non-branch ref, which is a different (and
		// non-real) contract, so restrict to the shape list actually sees.
		if err := m.Validate(); err != nil {
			return
		}

		got := HeadForList(m)

		// Determinism: a pure selector must return the same answer every call.
		if again := HeadForList(m); again != got {
			t.Fatalf("HeadForList not deterministic: %q then %q", got, again)
		}

		// Membership (the safety invariant): the advertised HEAD is empty or a
		// ref the manifest actually carries.
		assertHeadMembership(t, m, got)

		// Independently characterize the branch set the selector ranges over.
		bs := headBranchStats(m.Refs)

		// Emptiness is fully characterized by the branch set: HeadForList yields
		// "" exactly when the manifest carries no branch (validation forces a
		// live head to be a branch, so a head can never rescue a branchless one).
		if (got == "") != !bs.hasBranch {
			t.Fatalf("HeadForList = %q but hasBranch = %v", got, bs.hasBranch)
		}

		// Priority order: live head, then main, master, smallest branch.
		assertHeadPriority(t, m, bs, head, got)
	})
}

// FuzzPackHeadSniffer pins packHeadSniffer's two coupled contracts over an
// arbitrary pack stream delivered in arbitrary write-chunk boundaries: it must
// pass every byte through to the underlying writer unchanged and in order (it
// sits between git pack-objects and the encryptor, so any mutation or reorder
// would corrupt the on-disk ciphertext), and count() must report the big-endian
// uint32 at offset 8 of the header reassembled from however the first 12 bytes
// were split across Writes, or 0 when fewer than 12 bytes ever arrive. count()
// drives the push's empty-pack drop (push.go: "if bp.count > 0"), so a
// boundary-reassembly bug here would discard a real pack or publish an empty
// one. The oracle recomputes both expectations independently from the
// concatenated input, so it cannot merely restate the sniffer's chunk logic.
func FuzzPackHeadSniffer(f *testing.F) {
	// A genuine 12-byte PACK header ("PACK", version 2, count 1) plus a body.
	genuine := []byte{'P', 'A', 'C', 'K', 0, 0, 0, 2, 0, 0, 0, 1, 0xde, 0xad}
	// Seeds: real header in one shot, empty, sub-header (<12 bytes), the exact
	// 12-byte header alone, and a large count whose high bytes are set.
	f.Add(genuine, uint16(64))
	f.Add(genuine, uint16(1))
	f.Add(genuine, uint16(5))
	f.Add([]byte{}, uint16(1))
	f.Add([]byte{'P', 'A', 'C'}, uint16(1))
	f.Add([]byte{'P', 'A', 'C', 'K', 0, 0, 0, 2, 0, 0, 0, 7}, uint16(3))
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, uint16(2))

	f.Fuzz(func(t *testing.T, data []byte, chunk16 uint16) {
		chunk := int(chunk16)
		if chunk < 1 {
			chunk = 1
		}

		var sink bytes.Buffer
		s := &packHeadSniffer{dst: &sink}

		// Deliver the stream in chunk-sized writes, as a streaming pack-objects
		// would. bytes.Buffer never short-writes or errors, so the sniffer must
		// report the full chunk length and nil for every Write -- the property
		// that lets git stream the pack through to completion.
		for off := 0; off < len(data); off += chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			p := data[off:end]
			n, err := s.Write(p)
			if err != nil || n != len(p) {
				t.Fatalf("Write(%d bytes) = (%d, %v), want (%d, nil)", len(p), n, err, len(p))
			}
		}

		// Pass-through faithfulness: the sink holds exactly the input, unchanged.
		if got := sink.Bytes(); !bytes.Equal(got, data) {
			t.Fatalf("sniffer altered the stream: got %d bytes, want %d (equal=%v)",
				len(got), len(data), bytes.Equal(got, data))
		}

		// Independent count oracle: 0 until 12 bytes have arrived, then the
		// big-endian uint32 at offset 8 of the first 12 bytes of the stream.
		var want uint32
		if len(data) >= 12 {
			want = binary.BigEndian.Uint32(data[8:12])
		}
		if got := s.count(); got != want {
			t.Fatalf("count() = %d, want %d (stream=%d bytes, chunk=%d)", got, want, len(data), chunk)
		}
		// count() is a pure read: it must be stable across repeated calls.
		if again := s.count(); again != want {
			t.Fatalf("count() not stable: %d then %d", want, again)
		}
	})
}

// FuzzPackSkippable pins the fetch/apply-path skip gate over an arbitrary
// supersession structure: a pack with a fuzzed Replaces list, a fuzzed subset
// of those predecessors already marked applied, and a fuzzed local-closure
// verdict (the closure() fallback packSkippable consults when the replaces are
// not fully covered). The load-bearing contract is one-sided safety: a pack may
// be skipped via the replaces path ONLY when it is non-empty and every pack it
// replaces is already applied, so the skip provably delivers nothing new;
// anything else must download. The oracle re-derives coverage as a subset test
// independent of replacesCovered's loop, and additionally pins the closure-OR
// composition, the empty-replaces base case (a pack with no predecessors is
// never skipped on the replaces path), and monotonicity (marking more
// predecessors applied never un-covers a pack). The pack ID is a fixed 64-hex
// value because production only ever runs this gate on Validate-accepted
// manifests (whose ids are 64-hex) and the id's VALUE never affects the
// decision -- only Replaces membership and the closure do.
func FuzzPackSkippable(f *testing.F) {
	const validID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Seeds: both predecessors applied (covered), partial cover with closure
	// false (download) and true (skip via closure), no predecessors with each
	// closure verdict, and a lone predecessor not yet applied.
	f.Add("a\nb", uint16(0b11), false)
	f.Add("a\nb", uint16(0b01), false)
	f.Add("a\nb", uint16(0b01), true)
	f.Add("", uint16(0), false)
	f.Add("", uint16(0), true)
	f.Add("a", uint16(0), false)

	// A no-op logger: packSkippable logs on the covered path (p.ID[:12]); the
	// fixed 64-hex id keeps that slice in bounds exactly as a real manifest id
	// would, and discarding the output keeps the fuzzer fast and quiet.
	e := &Engine{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	f.Fuzz(func(t *testing.T, replacesBlob string, mask uint16, closureResult bool) {
		// The host-controlled predecessor ids. Empty tokens are dropped: a real
		// manifest pack id is never empty, and applied[""] would muddy the set.
		var replaces []string
		for _, r := range strings.Split(replacesBlob, "\n") {
			if r != "" {
				replaces = append(replaces, r)
			}
		}

		// Mark predecessor i applied iff bit i of the fuzzed mask is set. This
		// deterministically reaches the fully-covered and partially-covered
		// branches that blindly fuzzing a separate applied set would rarely hit.
		applied := map[string]bool{}
		for i, r := range replaces {
			if mask&(1<<(uint(i)%16)) != 0 {
				applied[r] = true
			}
		}

		p := manifest.Pack{ID: validID, Replaces: replaces}

		// Independent coverage oracle: covered iff the pack supersedes at least
		// one pack and every superseded id is in the applied SET (a subset test,
		// not replacesCovered's own loop).
		appliedSet := map[string]bool{}
		for r, ok := range applied {
			if ok {
				appliedSet[r] = true
			}
		}
		oracleCovered := len(replaces) > 0
		for _, r := range replaces {
			if !appliedSet[r] {
				oracleCovered = false
				break
			}
		}

		covered := replacesCovered(p, applied)
		if covered != oracleCovered {
			t.Fatalf("replacesCovered = %v, oracle = %v (replaces=%v applied=%v)",
				covered, oracleCovered, replaces, applied)
		}

		closure := func() bool { return closureResult }
		got := e.packSkippable(p, applied, closure)

		// Composition, one-sided safety, and the empty-replaces base case.
		assertSkippableSafety(t, got, covered, closureResult, replaces, appliedSet)

		// Determinism: a pure decision must repeat.
		if again := e.packSkippable(p, applied, closure); again != got {
			t.Fatalf("packSkippable not deterministic: %v then %v", got, again)
		}

		// Monotonicity: marking EVERY predecessor applied never un-covers a pack.
		assertSkippableMonotonic(t, p, replaces, covered)
	})
}

// FuzzRevListReportsMissing pins the rev-list --objects --missing=print parser
// over arbitrary git output. It is the closure verdict FuzzPackSkippable could
// only fuzz as an abstract bool: HasObjectClosure declares the local closure
// complete (and so lets downloadUnlessSkippable skip the download) ONLY when
// this parser finds no missing-object line, so under-reporting a "?" line would
// silently skip a pack the repo still needs objects for. The oracle re-derives
// the verdict by a forward "first non-whitespace byte is '?'" scan -- a
// different decomposition than the implementation's TrimSpace + HasPrefix -- so
// it catches a dropped trim, a Contains-for-HasPrefix slip, or a wrong line
// split rather than restating the parser. Seeds carry git's real output shape:
// present objects as "<oid> <path>" lines, missing ones as "?<oid>".
func FuzzRevListReportsMissing(f *testing.F) {
	const oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// Seeds: clean closure (no missing), a genuine missing line, missing among
	// present lines, leading whitespace before the marker (must still trip), a
	// '?' that is not at a line start (must NOT trip), an empty stream, a blank
	// trailing line, and a '?' alone.
	f.Add(oid + " a/b\n" + oid)
	f.Add("?" + oid)
	f.Add(oid + "\n?" + oid + "\n" + oid + " path")
	f.Add("   ?" + oid)
	f.Add(oid + " has?mark/in/path")
	f.Add("")
	f.Add(oid + "\n")
	f.Add("?")

	f.Fuzz(func(t *testing.T, out string) {
		got := revListReportsMissing(out)

		// Independent oracle: a line names a missing object iff, after dropping
		// leading whitespace, its first byte is '?'. ('?' is a single ASCII byte,
		// so a byte test matches HasPrefix's byte semantics exactly while the
		// trim-left + index decomposition is genuinely distinct from the
		// implementation's TrimSpace + HasPrefix.)
		want := false
		for _, line := range strings.Split(out, "\n") {
			s := strings.TrimLeftFunc(line, unicode.IsSpace)
			if len(s) > 0 && s[0] == '?' {
				want = true
				break
			}
		}
		if got != want {
			t.Fatalf("revListReportsMissing = %v, want %v (out=%q)", got, want, out)
		}

		// Determinism: a pure parser must return the same verdict every call.
		if again := revListReportsMissing(out); again != got {
			t.Fatalf("revListReportsMissing not deterministic: %v then %v", got, again)
		}
	})
}

// FuzzKeepFileFromIndexPack pins the apply-path keep-line parser over arbitrary
// index-pack stdout. The result becomes the helper's fetch "lock" line, so the
// parser must select the first "keep\t<hash>" line and build exactly the
// matching .keep path, and must report no lock ("") when none is present.
// The oracle re-derives the answer with a HasPrefix("keep\t") + TrimPrefix
// decomposition -- distinct from the implementation's strings.Cut + field
// equality -- so it catches a kind mis-compare, a wrong tab split, or a dropped
// line trim rather than restating the parser. Seeds carry git's real output
// shape (a single "keep\t<40-hex sha>" line) plus the boundary cases: no keep
// line, two keep lines (first wins), a keep line among noise, surrounding
// whitespace (trimmed), a "keep"-prefixed but non-keep field, and "keep" with
// no tab.
func FuzzKeepFileFromIndexPack(f *testing.F) {
	const gitDir = "/repo/.git"
	const sha = "473e11d032f32afbb521decfce93a38bb044627b"
	f.Add(gitDir, "keep\t"+sha)
	f.Add(gitDir, "")
	f.Add(gitDir, "keep\t"+sha+"\nkeep\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	f.Add(gitDir, "noise line\nkeep\t"+sha)
	f.Add(gitDir, "  keep\t"+sha+"  ")
	f.Add(gitDir, "keepx\tnotkeep")
	f.Add(gitDir, "keep")
	f.Add(gitDir, "keep\t")
	f.Add(gitDir, "\n\n")

	f.Fuzz(func(t *testing.T, gitDir, out string) {
		got := keepFileFromIndexPack(gitDir, out)

		// Independent oracle: walk the same trimmed-then-split lines, but detect
		// the keep line by prefix. kind=="keep" with a tab present is exactly
		// "the trimmed line begins with keep\t", and the hash is then everything
		// after that prefix (the same bytes strings.Cut returns after the first
		// tab). The first such line wins; absent one, there is no lock.
		want := ""
		matchedHash := ""
		matched := false
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "keep\t") {
				matchedHash = strings.TrimPrefix(trimmed, "keep\t")
				want = filepath.Join(gitDir, "objects", "pack", "pack-"+matchedHash+".keep")
				matched = true
				break
			}
		}
		if got != want {
			t.Fatalf("keepFileFromIndexPack = %q, want %q (out=%q)", got, want, out)
		}

		// Containment (the security-relevant property): a real pack hash is a
		// 40-hex sha with no path separator, so the lock path index-pack yields
		// always sits directly under gitDir/objects/pack and is named
		// pack-<hash>.keep. Asserted one-sided over separator-free hashes only,
		// because an adversarial hash bearing a separator is unreachable from
		// genuine index-pack output and the parser makes no promise about it.
		if matched && got != "" && !strings.ContainsRune(matchedHash, '/') &&
			!strings.ContainsRune(matchedHash, filepath.Separator) {
			if dir := filepath.Dir(got); dir != filepath.Join(gitDir, "objects", "pack") {
				t.Fatalf("lock path %q escaped objects/pack (dir=%q)", got, dir)
			}
			if base := filepath.Base(got); base != "pack-"+matchedHash+".keep" {
				t.Fatalf("lock path base = %q, want %q", base, "pack-"+matchedHash+".keep")
			}
		}

		// Determinism: a pure parser must return the same path every call.
		if again := keepFileFromIndexPack(gitDir, out); again != got {
			t.Fatalf("keepFileFromIndexPack not deterministic: %q then %q", got, again)
		}
	})
}

// FuzzPlanRefUpdatesDeletes pins the ref-DELETION authorization and projection
// path of planRefUpdates (and the delete branch of decideRef it drives) over an
// arbitrary remote ref set and an arbitrary batch of delete refspecs. A delete
// refspec has an empty Src, which is the one decideRef branch that runs no git
// subprocess, so the whole plan is purely fuzzable with no host. The gate is
// correctness-critical: a delete must be REJECTED ("remote ref does not exist")
// when its target is not on the remote and ACCEPTED -- removing the ref from the
// projected next-manifest ref set -- when it is, must never add a pack want for
// a delete, and must never mutate the caller's remoteRefs map (preparePush
// passes the live manifest.Refs map straight in, so an in-place edit would
// corrupt the cached remote state). The oracle re-derives the accept/reject
// verdict, the accepted count, and the projected ref set by independent map
// membership rather than restating the loop.
func FuzzPlanRefUpdatesDeletes(f *testing.F) {
	const oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// A small shared pool so a fuzzed delete target collides with a present ref
	// often enough to exercise the accept path (the steering technique iters
	// 43/48/49 use to reach an otherwise-rare branch).
	pool := []string{
		"refs/heads/main",
		"refs/heads/master",
		"refs/heads/dev",
		"refs/heads/feature",
		"refs/tags/v1",
		"refs/heads/zz",
	}
	const absent = "refs/heads/__absent__" // never in the pool, so never present

	// Seeds: delete a present ref, delete an absent ref, duplicate delete of one
	// present ref, the guaranteed-absent sentinel, an empty-dst delete, all
	// targets absent and force-flagged, and an empty batch.
	f.Add(uint8(0b000001), []byte{0}, uint16(0))
	f.Add(uint8(0b000001), []byte{1}, uint16(0))
	f.Add(uint8(0b000001), []byte{0, 0}, uint16(0))
	f.Add(uint8(0b111111), []byte{6}, uint16(0))
	f.Add(uint8(0b001000), []byte{7}, uint16(0))
	f.Add(uint8(0), []byte{0, 1, 2}, uint16(0xffff))
	f.Add(uint8(0), []byte{}, uint16(0))

	// Delete refspecs never reach decideRef's git calls, so a zero Engine is safe.
	e := &Engine{}

	f.Fuzz(func(t *testing.T, presentMask uint8, dstSeq []byte, forceMask uint16) {
		// Build the remote ref set from the pool entries selected by presentMask.
		remoteRefs := map[string]string{}
		for i, name := range pool {
			if presentMask&(uint8(1)<<uint(i)) != 0 {
				remoteRefs[name] = oid
			}
		}

		// Build the delete batch. Each byte selects a target: a pool ref (so it
		// may collide with a present ref), the guaranteed-absent sentinel, or an
		// empty name. Src is always "" -> every update is a delete.
		updates := make([]RefUpdate, 0, len(dstSeq))
		for i, b := range dstSeq {
			updates = append(updates, RefUpdate{
				Src:   "",
				Dst:   pickCandidate(b, pool, absent),
				Force: forceMask&(uint16(1)<<uint(i%16)) != 0,
			})
		}

		// Snapshot the input map: planRefUpdates must not mutate it (preparePush
		// hands it the live manifest.Refs map).
		before := maps.Clone(remoteRefs)

		results, newRefs, wants, accepted := e.planRefUpdates(remoteRefs, updates)

		if !maps.Equal(remoteRefs, before) {
			t.Fatalf("planRefUpdates mutated its input remoteRefs map: before=%v after=%v", before, remoteRefs)
		}

		// Authorization, projection, accepted count, and pack-want freedom, each
		// re-derived against the ORIGINAL remote ref set.
		assertDeletePlan(t, results, newRefs, wants, accepted, updates, before)

		// Determinism: the same batch re-plans to the same projection.
		results2, newRefs2, wants2, accepted2 := e.planRefUpdates(remoteRefs, updates)
		if accepted2 != accepted || len(wants2) != len(wants) || !maps.Equal(newRefs2, newRefs) {
			t.Fatalf("planRefUpdates not deterministic")
		}
		for i := range results2 {
			if results2[i] != results[i] {
				t.Fatalf("planRefUpdates results not deterministic at %d: %v vs %v", i, results2[i], results[i])
			}
		}
	})
}

// FuzzRepackManifest pins repackManifest, the next-generation manifest builder
// for a full repack (consolidate.go). It asserts, over an arbitrary current
// manifest and merged-pack id/size: the generation is bumped by exactly one, the
// pack set becomes the single merged pack carrying every prior pack id (in
// order, no drop/dup/reorder) as Replaces, the version/repo-id/head/refs are
// carried forward unchanged, the produced manifest is isolated from the input
// (scribbling it never corrupts cur, which repackOnce keeps using on a lost-CAS
// retry), and the build is deterministic. The Replaces-lists-every-prior-id
// contract is the load-bearing one: it is what lets a client that already
// applied the old packs skip re-downloading the merged pack (packSkippable).
func FuzzRepackManifest(f *testing.F) {
	const (
		oid40  = "1111111111111111111111111111111111111111"
		repo32 = "0123456789abcdef0123456789abcdef"
		id64   = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	)
	// Seeds: a typical multi-pack repack, an empty old-pack set, a single old
	// pack, the generation-wraps-to-zero edge, and duplicate old ids with a
	// negative size (repackManifest copies fields faithfully without validating).
	f.Add(uint64(5), []byte{0, 1, 2}, "refs/heads/dev", oid40, "refs/heads/main", repo32, id64, int64(4096))
	f.Add(uint64(0), []byte{}, "", "", "", "", "", int64(0))
	f.Add(uint64(1), []byte{9}, "refs/tags/v1", oid40, "", repo32, id64, int64(1))
	f.Add(^uint64(0), []byte{0}, "", "", "", repo32, id64, int64(1<<40))
	f.Add(uint64(42), []byte{7, 7, 7}, "refs/heads/x", oid40, "refs/heads/x", repo32, id64, int64(-1))

	f.Fuzz(func(t *testing.T, gen uint64, packSeed []byte, refName, refOID, head, repoID, newID string, newSize int64) {
		// Build cur's manifest: arbitrary carried-over fields plus one old pack
		// per packSeed byte (id derived from the byte; duplicates allowed, exactly
		// as a real manifest may carry whatever ids were live).
		refs := map[string]string{"refs/heads/main": oid40}
		if refName != "" {
			refs[refName] = refOID
		}
		oldPacks := make([]manifest.Pack, 0, len(packSeed))
		for _, b := range packSeed {
			oldPacks = append(oldPacks, manifest.Pack{ID: fmt.Sprintf("%064x", b), Size: int64(b)})
		}
		cur := &RemoteState{Manifest: &manifest.Manifest{
			Version:    manifest.Version,
			RepoID:     repoID,
			Generation: gen,
			Head:       head,
			Refs:       refs,
			Packs:      oldPacks,
		}}

		// Independent snapshot of cur (NOT via manifest.Clone, so the no-mutation
		// oracle does not depend on the Clone implementation).
		snapRefs := maps.Clone(refs)
		wantOldIDs := make([]string, 0, len(oldPacks))
		for _, p := range oldPacks {
			wantOldIDs = append(wantOldIDs, p.ID)
		}

		man := repackManifest(cur, newID, newSize)

		// Generation bump, single merged pack carrying every prior id as Replaces,
		// and carry-over of version/repo-id/head/refs.
		assertRepackResult(t, man, gen, newID, newSize, wantOldIDs, repoID, head, snapRefs)

		// Isolation: scribbling the result must not corrupt cur's manifest
		// (repackOnce keeps using cur on a lost-CAS retry).
		man.Generation = 999
		man.RepoID = "MUTATED"
		man.Head = "MUTATED"
		man.Refs["refs/heads/injected"] = "x"
		man.Packs[0].ID = "MUTATED"
		if len(man.Packs[0].Replaces) > 0 {
			man.Packs[0].Replaces[0] = "MUTATED"
		}
		assertCurUnmutated(t, cur, gen, repoID, head, snapRefs, wantOldIDs)

		// Determinism: cur is now verified clean, so a re-build reproduces it.
		man2 := repackManifest(cur, newID, newSize)
		if man2.Generation != gen+1 || len(man2.Packs) != 1 ||
			man2.Packs[0].ID != newID || man2.Packs[0].Size != newSize ||
			!slices.Equal(man2.Packs[0].Replaces, wantOldIDs) {
			t.Fatalf("repackManifest not deterministic")
		}
	})
}

// planPacksFrom builds the plannedPack slice for the fuzzers from a single
// (id, size): empty when id is "", mirroring the pre-slice "append iff id != \"\""
// contract that nextPushManifest still upholds per pack.
func planPacksFrom(id string, size int64) []plannedPack {
	if id == "" {
		return nil
	}
	return []plannedPack{{id: id, size: size}}
}

// FuzzNextPushManifest pins nextPushManifest, the normal-push manifest builder
// and the write-side counterpart to FuzzRepackManifest (which covers the rarer
// FullRepack builder). assembleManifest resolves the random repo id and the git
// HEAD symref, then hands the pure construction to nextPushManifest, so the
// builder is fuzzable in-memory with no host. assembleManifest DOES Validate the
// result, but Validate enforces neither "the generation advanced by exactly one"
// nor "every prior live pack is retained": a builder that silently dropped a
// prior pack or mis-bumped the generation would still produce a VALID manifest,
// so those data-continuity / rollback invariants need a direct pin. The oracle
// snapshots base independently of manifest.Clone (maps.Clone + scalar capture)
// so a Clone regression cannot mask a nextPushManifest aliasing bug.
func FuzzNextPushManifest(f *testing.F) {
	const (
		oid40  = "1111111111111111111111111111111111111111"
		repo32 = "0123456789abcdef0123456789abcdef"
		id64   = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	)
	// Seeds: a typical multi-pack base with a new pack appended, an empty base
	// with no new pack (a manifest-only push), a single old pack, the
	// generation-wraps-to-zero edge, and a duplicate-id base.
	f.Add(uint64(5), []byte{0, 1, 2}, "refs/heads/main", oid40, "refs/heads/main", repo32, id64, int64(4096))
	f.Add(uint64(0), []byte{}, "", "", "", repo32, "", int64(0))
	f.Add(uint64(1), []byte{9}, "refs/tags/v1", oid40, "refs/tags/v1", repo32, id64, int64(1))
	f.Add(^uint64(0), []byte{0}, "refs/heads/x", oid40, "", repo32, id64, int64(1<<40))
	f.Add(uint64(42), []byte{7, 7}, "refs/heads/dev", oid40, "refs/heads/dev", repo32, id64, int64(-1))

	f.Fuzz(func(t *testing.T, gen uint64, packSeed []byte, newRefName, newRefOID, head, repoID, newID string, newSize int64) {
		// base: arbitrary carried-over fields plus one old pack per packSeed byte
		// (ids derived from the byte; duplicates allowed, exactly as a live
		// manifest may carry whatever ids were last pushed). base.Refs/base.Head
		// are deliberately set to values DISTINCT from the ones being installed,
		// so the oracle observes an install (overwrite) rather than a carry-over.
		oldPacks := make([]manifest.Pack, 0, len(packSeed))
		for _, b := range packSeed {
			oldPacks = append(oldPacks, manifest.Pack{ID: fmt.Sprintf("%064x", b), Size: int64(b)})
		}
		base := &manifest.Manifest{
			Version:    manifest.Version,
			RepoID:     repoID,
			Generation: gen,
			Head:       "refs/heads/base-only",
			Refs:       map[string]string{"refs/heads/base-only": oid40},
			Packs:      oldPacks,
		}

		// newRefs: the ref set being published this push.
		newRefs := map[string]string{}
		if newRefName != "" {
			newRefs[newRefName] = newRefOID
		}

		// Independent snapshots of base (NOT via manifest.Clone) and of newRefs.
		snapBaseRefs := maps.Clone(base.Refs)
		wantOldIDs := make([]string, 0, len(oldPacks))
		wantOldSizes := make([]int64, 0, len(oldPacks))
		for _, p := range oldPacks {
			wantOldIDs = append(wantOldIDs, p.ID)
			wantOldSizes = append(wantOldSizes, p.Size)
		}
		wantNewRefs := maps.Clone(newRefs)

		man := nextPushManifest(base, newRefs, head, planPacksFrom(newID, newSize))

		// Generation bump, wholesale install of the published ref set/head, and
		// carry-over of version/repo identity.
		assertPushInstall(t, man, gen, wantNewRefs, head, repoID)
		// Pack continuity: every prior pack retained in order, the new pack
		// appended iff packID != "".
		assertPackContinuity(t, man, wantOldIDs, wantOldSizes, newID, newSize)

		// Isolation: scribbling the result must not corrupt base (pushOnce keeps
		// using cur on a lost-CAS retry; base may alias the cached remote state).
		man.Generation = 12345
		man.RepoID = "MUTATED"
		man.Head = "MUTATED"
		man.Refs["refs/heads/injected"] = "x"
		for i := range man.Packs {
			man.Packs[i].ID = "MUTATED"
		}
		assertBaseUnmutated(t, base, gen, repoID, snapBaseRefs, wantOldIDs)

		// Determinism: base is verified clean, so a rebuild reproduces the result
		// (a fresh newRefs clone, since the scribble above mutated the aliased one).
		// The scribble left man.Packs's length intact, so it stands in for the
		// expected pack count.
		man2 := nextPushManifest(base, maps.Clone(wantNewRefs), head, planPacksFrom(newID, newSize))
		if man2.Generation != gen+1 || man2.Head != head || man2.RepoID != repoID ||
			!maps.Equal(man2.Refs, wantNewRefs) || len(man2.Packs) != len(man.Packs) {
			t.Fatalf("nextPushManifest not deterministic")
		}
	})
}

// FuzzSelectManifestHead pins selectManifestHead, the push-side head selector,
// over an arbitrary (local HEAD symref, its validity, previous head, ref set).
// It is the WRITE-side counterpart to FuzzHeadForList: this chooses the head to
// PUBLISH into the next manifest, which HeadForList then advertises on list. The
// load-bearing contract is membership safety -- a non-empty result is always a
// ref the manifest carries -- plus the documented priority (local HEAD branch >
// previous head > none) and the precedence that the previous head is consulted
// ONLY when the local HEAD is unusable. local, prev.Head and the ref set are
// drawn from a small shared pool by selector so the in-refs collisions that
// reach the accept paths are frequent (the steering iters 43/48/49/53 use).
func FuzzSelectManifestHead(f *testing.F) {
	const oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// A small pool plus two off-pool sentinels: "" (detached/empty) and a name
	// the ref set never holds, so the dangling-head fallthrough is reachable.
	pool := []string{
		"refs/heads/main",
		"refs/heads/dev",
		"refs/heads/master",
		"refs/tags/v1",
	}
	const offPool = "refs/heads/__off__" // never added to refs
	// pickCandidate maps each selector byte to a pool ref, the off-pool name, or
	// "", so local/prevHead range over present, absent, and empty values.

	// Seeds: local present (wins), local absent with prev present (prev wins),
	// local present AND prev present (local still wins), neither usable (empty),
	// local valid but symref failed (localOK=false skips local), no prev at all,
	// and empty local with empty ref set.
	f.Add(uint8(0b0001), uint8(0), true, uint8(1), true)
	f.Add(uint8(0b0011), uint8(4), true, uint8(1), true)
	f.Add(uint8(0b0011), uint8(0), true, uint8(1), true)
	f.Add(uint8(0b0100), uint8(0), true, uint8(4), true)
	f.Add(uint8(0b0001), uint8(0), false, uint8(0), true)
	f.Add(uint8(0b0001), uint8(0), true, uint8(5), false)
	f.Add(uint8(0), uint8(5), true, uint8(5), false)

	f.Fuzz(func(t *testing.T, refsMask uint8, localSel uint8, localOK bool, prevSel uint8, hasPrev bool) {
		// Build the ref set from the pool entries the mask selects.
		refs := map[string]string{}
		for i, name := range pool {
			if refsMask&(uint8(1)<<uint(i)) != 0 {
				refs[name] = oid
			}
		}
		local := pickCandidate(localSel, pool, offPool)
		prevHead := pickCandidate(prevSel, pool, offPool)

		var prev *manifest.Manifest
		if hasPrev {
			// Only Head is read; carry a plausible rest so prev is a real manifest.
			prev = &manifest.Manifest{Version: manifest.Version, Head: prevHead, Refs: map[string]string{}}
		}

		got := selectManifestHead(local, localOK, prev, refs)

		// Membership safety and provenance: a non-empty head is always a ref the
		// manifest carries, and only ever one of the two candidate inputs.
		assertSelectHeadSafety(t, got, local, prevHead, hasPrev, refs)

		// Whether each candidate is usable, derived independently of the cascade
		// (a separate map read, not selectManifestHead's own membership test).
		_, localInRefs := refs[local]
		_, prevInRefs := refs[prevHead]
		localUsable := localOK && localInRefs
		prevUsable := hasPrev && prevHead != "" && prevInRefs

		// Priority cascade (local wins, else prev, else none) and emptiness.
		assertSelectHeadCascade(t, got, local, prevHead, localUsable, prevUsable)

		// Determinism: a pure selector must repeat.
		if again := selectManifestHead(local, localOK, prev, refs); again != got {
			t.Fatalf("selectManifestHead not deterministic: %q then %q", got, again)
		}
	})
}

// FuzzFastForwardExempt pins fastForwardExempt, the pure gate lifted out of
// nonFastForwardReason that decides whether a push may be accepted without the
// git ancestry check. The function reads only remoteRefs[u.Dst], so the fuzz
// drives exactly what matters: whether dst is present, dst's stored tip, the
// refOID being published, and the force flag (a small oid pool makes the
// unchanged-tip "old == refOID" exempt branch frequent, the steering iters
// 43/48/49/53/55 use). The load-bearing oracle is the security invariant -- a
// non-force tip change on an existing ref is never exempt -- expressed as a harm
// statement rather than a restatement of the boolean, plus the dual that every
// individual exempt cause forces a true result.
func FuzzFastForwardExempt(f *testing.F) {
	const dst = "refs/heads/main"
	// A small oid pool (including "") shared between stored tips and refOID so
	// the unchanged-tip (old == refOID) exempt branch is reached often; random
	// 40-hex strings would essentially never collide.
	oids := []string{
		"1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333",
		"",
	}
	pickOID := func(sel uint8) string { return oids[int(sel)%len(oids)] }

	// Seeds: each exempt cause and the one non-exempt case.
	f.Add(false, uint8(0), uint8(0), false) // dst absent -> exempt (new ref)
	f.Add(true, uint8(0), uint8(0), false)  // present, old == refOID -> exempt (no-op)
	f.Add(true, uint8(0), uint8(1), true)   // present, tip changed, forced -> exempt
	f.Add(true, uint8(0), uint8(1), false)  // present, tip changed, NOT forced -> NOT exempt
	f.Add(true, uint8(3), uint8(3), false)  // present, both "" -> exempt (no-op, empty oids)

	f.Fuzz(func(t *testing.T, present bool, storedSel, refSel uint8, force bool) {
		storedOID := pickOID(storedSel)
		refOID := pickOID(refSel)

		// remoteRefs carries dst only when present, plus a noise entry the gate
		// must never read (it looks up u.Dst alone) -- a wrong-key read would be
		// caught by the faithfulness oracle below.
		refs := map[string]string{
			"refs/heads/other": "9999999999999999999999999999999999999999",
		}
		if present {
			refs[dst] = storedOID
		}
		u := RefUpdate{Src: "refs/heads/local", Dst: dst, Force: force}

		got := fastForwardExempt(u, refs, refOID)

		// Re-derive presence and the stored tip independently of the gate.
		old, exists := refs[dst]

		// The load-bearing SECURITY invariant: a non-force push that changes an
		// EXISTING ref's tip must NEVER be exempt -- it has to fall through to the
		// HaveObject/merge-base ancestry test. Exempting it would accept a silent
		// non-fast-forward history rewrite without any verification.
		if exists && !force && old != refOID && got {
			t.Fatalf("non-force tip change on existing ref %q (%q -> %q) was exempted from the ancestry check",
				dst, old, refOID)
		}

		// The dual: each exempt cause -- new ref, forced push, or unchanged tip --
		// must on its own produce a true result, so a genuinely allowed update is
		// never needlessly forced through the ancestry test.
		exemptCause := !exists || force || (exists && old == refOID)
		if exemptCause && !got {
			t.Fatalf("an exempt cause held (new=%v force=%v unchanged=%v) but fastForwardExempt returned false",
				!exists, force, exists && old == refOID)
		}
		// Together the two checks above fully characterize the gate, so the result
		// must equal the exempt-cause disjunction.
		if got != exemptCause {
			t.Fatalf("fastForwardExempt(present=%v stored=%q refOID=%q force=%v) = %v, want %v",
				present, storedOID, refOID, force, got, exemptCause)
		}

		// Determinism: a pure gate must repeat.
		if again := fastForwardExempt(u, refs, refOID); again != got {
			t.Fatalf("fastForwardExempt not deterministic: %v then %v", got, again)
		}
	})
}

// FuzzRetainLivePackBlobs pins retainLivePackBlobs, the commit-building blob
// reuse filter, together with manifest.PackIDs() that feeds it. The manifest's
// live pack ids are drawn from a small pool; the host blob map is drawn from a
// WIDER id space (the pool plus two "ghost" ids the manifest never carries), so
// the drop branch -- a host blob whose pack id is not live -- is reached often,
// the steering iters 43/48/49/53/55/57 use. The independent oracle re-derives
// the live set from the manifest packs (not via PackIDs) and the kept map by set
// intersection (not via the production loop), so it catches a PackIDs drift, a
// dropped-live-pack regression, a surviving non-live blob, or a mutated oid. The
// load-bearing harm statement is explicit: no surviving blob may name a pack id
// the manifest does not declare live, since such a blob would enter the
// published commit tree as a reference the manifest cannot account for.
func FuzzRetainLivePackBlobs(f *testing.F) {
	// pool: pack ids the manifest may carry. idSpace: the wider id space the host
	// blob map may reference (pool + two ghosts), so a host can present a blob for
	// a pack the manifest never declared live.
	const poolSize = 6
	pool := make([]string, poolSize)
	for i := range pool {
		pool[i] = fmt.Sprintf("%064x", i)
	}
	idSpace := append(append([]string{}, pool...), fmt.Sprintf("%064x", 200), fmt.Sprintf("%064x", 201))

	// Seeds: live + host overlap with a ghost, no live packs (all dropped), no
	// host blobs (empty result), full overlap (all kept), and a duplicate live id
	// (PackIDs collapses it) with a host ghost.
	f.Add([]byte{0, 1, 2}, []byte{0, 1, 6})
	f.Add([]byte{}, []byte{0, 1})
	f.Add([]byte{0, 1, 2}, []byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte{0, 0, 0}, []byte{0, 7})

	f.Fuzz(func(t *testing.T, livePackSeed, hostBlobSeed []byte) {
		// Build the manifest: one pack per livePackSeed byte (id from the pool,
		// duplicates allowed exactly as a live manifest may carry).
		packs := make([]manifest.Pack, 0, len(livePackSeed))
		for _, b := range livePackSeed {
			packs = append(packs, manifest.Pack{ID: pool[int(b)%len(pool)], Size: int64(b)})
		}
		m := &manifest.Manifest{Packs: packs}

		// Production live set, plus an independent set built directly from packs.
		live := m.PackIDs()
		liveOracle := map[string]bool{}
		for _, p := range packs {
			liveOracle[p.ID] = true
		}
		if !maps.Equal(live, liveOracle) {
			t.Fatalf("PackIDs() = %v, want %v", live, liveOracle)
		}

		// Build the host blob map: one entry per hostBlobSeed byte, id from the
		// wider idSpace (so ghosts appear), oid distinct per position (last-wins on
		// a repeated id, exactly as map assignment does).
		host := map[string]string{}
		for i, b := range hostBlobSeed {
			host[idSpace[int(b)%len(idSpace)]] = fmt.Sprintf("%040x", i)
		}
		orig := maps.Clone(host)

		retainLivePackBlobs(host, live)

		// Independent expected map: keep an original entry IFF its id is live,
		// preserving its exact oid. maps.Equal then pins all of: no fabricated key,
		// no stale (non-live) survivor, no dropped live key, no mutated oid.
		expected := map[string]string{}
		for id, oid := range orig {
			if liveOracle[id] {
				expected[id] = oid
			}
		}
		if !maps.Equal(host, expected) {
			t.Fatalf("retainLivePackBlobs = %v, want %v (orig=%v live=%v)", host, expected, orig, live)
		}

		// Load-bearing harm statement: no surviving blob names a non-live pack id.
		// Such a blob would enter the published commit tree as a reference the
		// manifest does not account for.
		for id := range host {
			if !liveOracle[id] {
				t.Fatalf("blob for non-live pack id %q survived the filter", id)
			}
		}

		// Idempotence: re-filtering an already-filtered map changes nothing.
		retainLivePackBlobs(host, live)
		if !maps.Equal(host, expected) {
			t.Fatalf("retainLivePackBlobs not idempotent: %v want %v", host, expected)
		}

		// Determinism: filtering a fresh copy of the original reproduces the result.
		again := maps.Clone(orig)
		retainLivePackBlobs(again, live)
		if !maps.Equal(again, expected) {
			t.Fatalf("retainLivePackBlobs not deterministic")
		}
	})
}

// FuzzConsolidatedPacks pins consolidatedPacks, the geometric-consolidation
// pack-set builder (consolidate.go), over an arbitrary live pack set, an
// arbitrary victim id list, and an arbitrary merged-pack id/size. The live pack
// ids are drawn from a small pool and the victim ids from a WIDER id space (the
// pool plus two ghost ids the manifest never carries) so the drop branch and the
// supersede-a-ghost edge are both reached often, the steering iters
// 43/48/49/53/55/57/59 use. The load-bearing invariant ties to packSkippable:
// every live pack must end up either retained as a survivor or declared
// superseded in the merged pack's Replaces -- a live pack that vanished without
// being declared replaced would be silently re-downloaded-skipped by a client
// that never applied it. The oracle re-derives the survivor set with a
// slices.Contains linear-scan membership test (a decomposition distinct from the
// implementation's map lookup), so it catches a victim-set build bug, a dropped
// survivor, a surviving victim, or a wrong Replaces list, and verifies no input
// slice is mutated (applyConsolidation reuses plan.man.Packs in place).
func FuzzConsolidatedPacks(f *testing.F) {
	const id64 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	// pool: pack ids the live manifest may carry. idSpace: the wider id space the
	// victim list may reference (pool + two ghosts), so a victim may match a live
	// pack or be an id the live set never carried.
	const poolSize = 6
	pool := make([]string, poolSize)
	for i := range pool {
		pool[i] = fmt.Sprintf("%064x", i)
	}
	idSpace := append(append([]string{}, pool...), fmt.Sprintf("%064x", 200), fmt.Sprintf("%064x", 201))

	// Seeds: typical (some live, victims overlap two of them), no victims (all
	// retained), every live pack a victim (all dropped), duplicate live id with a
	// single victim, victims that are only ghosts (nothing dropped, ghosts still
	// listed in Replaces), and an empty live set.
	f.Add([]byte{0, 1, 2, 3}, []byte{0, 1}, id64, int64(8192))
	f.Add([]byte{0, 1, 2}, []byte{}, id64, int64(0))
	f.Add([]byte{0, 1, 2}, []byte{0, 1, 2}, id64, int64(4096))
	f.Add([]byte{0, 0, 1}, []byte{0}, id64, int64(1))
	f.Add([]byte{0, 1}, []byte{6, 7}, id64, int64(123))
	f.Add([]byte{}, []byte{0}, id64, int64(5))

	f.Fuzz(func(t *testing.T, livePackSeed, victimSeed []byte, mergedID string, mergedSize int64) {
		// Live pack set: one pack per livePackSeed byte (id from the pool,
		// duplicates allowed exactly as a live manifest may carry, a distinct Size
		// and a per-pack Replaces so survivor faithfulness covers the slice field).
		packs := make([]manifest.Pack, 0, len(livePackSeed))
		for i, b := range livePackSeed {
			packs = append(packs, manifest.Pack{
				ID:       pool[int(b)%len(pool)],
				Size:     int64(i),
				Replaces: []string{fmt.Sprintf("%064x", 100+i)},
			})
		}

		// Victim id list: each byte selects an id from the wider id space, so a
		// victim may match a live pack or be a ghost the live set never carried.
		victimIDs := make([]string, 0, len(victimSeed))
		for _, b := range victimSeed {
			victimIDs = append(victimIDs, idSpace[int(b)%len(idSpace)])
		}

		// Snapshot inputs to verify consolidatedPacks mutates neither.
		packsSnap := slices.Clone(packs)
		victimSnap := slices.Clone(victimIDs)

		got := consolidatedPacks(packs, victimIDs, mergedID, mergedSize)

		// Independent survivor set: the live packs whose id is not a victim (a
		// linear slices.Contains scan, not the implementation's map lookup, so a
		// victim-set build bug is caught).
		var wantSurvivors []manifest.Pack
		for _, p := range packs {
			if !slices.Contains(victimIDs, p.ID) {
				wantSurvivors = append(wantSurvivors, p)
			}
		}

		// Shape: survivors verbatim in order, then the one merged pack carrying
		// the victim list as Replaces.
		assertConsolidatedShape(t, got, wantSurvivors, mergedID, mergedSize, victimIDs)
		// Load-bearing harm statement: every live pack is retained or superseded,
		// and no survivor is itself a victim.
		assertConsolidationComplete(t, got, packs, victimIDs)
		// No input mutation: packs/victimIDs survive the call unchanged.
		assertConsolidatedNoMutation(t, packs, packsSnap, victimIDs, victimSnap)

		// Determinism: a fresh copy of the inputs reproduces the same pack set.
		got2 := consolidatedPacks(slices.Clone(packs), slices.Clone(victimIDs), mergedID, mergedSize)
		if len(got2) != len(got) {
			t.Fatalf("consolidatedPacks not deterministic (len %d != %d)", len(got2), len(got))
		}
		for i := range got {
			if !packFieldsEqual(got2[i], got[i]) {
				t.Fatalf("consolidatedPacks not deterministic at %d", i)
			}
		}
	})
}

// FuzzCanMarkConsolidated pins canMarkConsolidated, the consolidation's
// mark-applied gate (consolidate.go), over an arbitrary victim id list, an
// arbitrary applied set, and an arbitrary choice of not-yet-pushed pack id. The
// victim ids are drawn from a WIDER id space (a pool the applied set ranges over
// plus two ghosts the applied set never carries) and the not-yet-pushed id is
// selected from that space plus "" (the packless-plan case), the pool+ghost
// steering iters 53/59/60 use, so both the safe-victim and unsafe-victim
// branches are reached often. The load-bearing invariant is the one-sided floor:
// canMark is true ONLY when every victim is covered (the not-yet-pushed pack or
// already applied) -- a wrong true would record the merged pack as applied while
// some never-applied victim's objects are absent locally, so a future fetch
// would skip its download forever. The oracle re-derives the verdict by building
// the covered set as a UNION (applied keys plus the not-yet-pushed id) and
// asserting every victim is in it, a decomposition distinct from the
// implementation's per-victim "is-not-the-pushed-pack AND not-applied" flip, so
// it catches a dropped applied check, a flipped equality, or a wrong victim-id
// order, and verifies neither input is mutated.
func FuzzCanMarkConsolidated(f *testing.F) {
	// pool: ids the applied set ranges over. idSpace: the wider space a victim id
	// may take (pool + two ghosts the applied set never carries). notYetChoices:
	// idSpace plus "" (a packless plan's empty packID, which no 64-hex victim
	// matches -- exactly as in production).
	const poolSize = 6
	pool := make([]string, poolSize)
	for i := range pool {
		pool[i] = fmt.Sprintf("%064x", i)
	}
	idSpace := append(append([]string{}, pool...), fmt.Sprintf("%064x", 200), fmt.Sprintf("%064x", 201))
	notYetChoices := append(append([]string{}, idSpace...), "")

	// Seeds: all victims applied (canMark true), ghost victims with no applied and
	// empty pushed-id (false), all victims equal the not-yet-pushed pack (true),
	// no victims (vacuously true), one applied + one unapplied (false), and a
	// ghost victim covered by the not-yet-pushed id alongside an applied one (true).
	f.Add([]byte{0, 1, 2}, uint16(0b111), uint8(0))
	f.Add([]byte{6, 7}, uint16(0), uint8(len(notYetChoices)-1))
	f.Add([]byte{3, 3, 3}, uint16(0), uint8(3))
	f.Add([]byte{}, uint16(0), uint8(len(notYetChoices)-1))
	f.Add([]byte{0, 1}, uint16(0b1), uint8(len(notYetChoices)-1))
	f.Add([]byte{6, 0}, uint16(0b1), uint8(6))

	f.Fuzz(func(t *testing.T, victimSeed []byte, appliedMask uint16, notYetSel uint8) {
		// Victim packs: one per victimSeed byte, id from the wider id space (so a
		// victim may be a pool id or a ghost), with a distinct Size that must not
		// affect the decision (only the id matters).
		victims := make([]manifest.Pack, 0, len(victimSeed))
		for i, b := range victimSeed {
			victims = append(victims, manifest.Pack{ID: idSpace[int(b)%len(idSpace)], Size: int64(i)})
		}

		// Applied set: pool id i is applied iff bit i of the mask is set.
		applied := map[string]bool{}
		for i := range pool {
			if appliedMask&(1<<uint(i)) != 0 {
				applied[pool[i]] = true
			}
		}
		notYetPushedID := notYetChoices[int(notYetSel)%len(notYetChoices)]

		// Snapshot inputs to confirm canMarkConsolidated mutates neither.
		victimSnap := slices.Clone(victims)
		appliedSnap := maps.Clone(applied)

		gotIDs, gotCanMark := canMarkConsolidated(victims, notYetPushedID, applied)

		// victimIDs order, the covered-as-union verdict, and the one-sided floor.
		assertCanMarkVerdict(t, gotIDs, gotCanMark, victims, notYetPushedID, applied)

		// Determinism: same inputs, same answer.
		gotIDs2, gotCanMark2 := canMarkConsolidated(victims, notYetPushedID, applied)
		if gotCanMark2 != gotCanMark || !slices.Equal(gotIDs2, gotIDs) {
			t.Fatalf("canMarkConsolidated not deterministic")
		}

		// No input mutation: victims and applied survive the call unchanged.
		assertCanMarkNoMutation(t, victims, victimSnap, applied, appliedSnap)
	})
}

// pickCandidate maps a fuzz selector byte to one of three classes of value: a
// pool entry (so it may collide with a present ref/pack), the off-pool sentinel,
// or "". Shared by the delete-target and head-candidate fuzzers, whose selection
// shape is identical.
func pickCandidate(sel uint8, pool []string, sentinel string) string {
	n := int(sel) % (len(pool) + 2)
	switch {
	case n < len(pool):
		return pool[n]
	case n == len(pool):
		return sentinel
	default:
		return ""
	}
}

// packFieldsEqual compares two packs by every field including the Replaces slice
// (survivors are carried over verbatim, so their Replaces must survive too).
func packFieldsEqual(a, b manifest.Pack) bool {
	return a.ID == b.ID && a.Size == b.Size && slices.Equal(a.Replaces, b.Replaces)
}

// headBranchInfo characterizes the refs/heads/ subset of a manifest's ref set
// that HeadForList's fallback selection ranges over.
type headBranchInfo struct {
	hasBranch          bool
	minBranch          string
	hasMain, hasMaster bool
}

// headBranchStats independently derives the branch set HeadForList selects over:
// whether any branch exists, the lexicographically smallest one, and whether the
// two privileged names are present.
func headBranchStats(refs map[string]string) headBranchInfo {
	var bs headBranchInfo
	for name := range refs {
		if !strings.HasPrefix(name, "refs/heads/") {
			continue
		}
		bs.hasBranch = true
		if bs.minBranch == "" || name < bs.minBranch {
			bs.minBranch = name
		}
		switch name {
		case "refs/heads/main":
			bs.hasMain = true
		case "refs/heads/master":
			bs.hasMaster = true
		}
	}
	return bs
}

// assertHeadMembership pins HeadForList's load-bearing safety invariant: a
// non-empty advertised HEAD must name a ref the manifest actually carries, and a
// validated/fallback head is always a branch.
func assertHeadMembership(t *testing.T, m *manifest.Manifest, got string) {
	t.Helper()
	if got == "" {
		return
	}
	if _, ok := m.Refs[got]; !ok {
		t.Fatalf("HeadForList = %q, which is not a ref in the manifest", got)
	}
	// A validated head is a branch and every fallback is a branch, so a non-empty
	// result is always under refs/heads/.
	if !strings.HasPrefix(got, "refs/heads/") {
		t.Fatalf("HeadForList = %q, which is not a branch ref", got)
	}
}

// assertHeadPriority pins HeadForList's documented priority: a live head wins
// outright, else main, else master, else the lexicographically smallest branch
// (asserted as a universal minimum rather than by re-sorting, so it does not
// merely restate the implementation).
func assertHeadPriority(t *testing.T, m *manifest.Manifest, bs headBranchInfo, head, got string) {
	t.Helper()
	// A head that names a live ref always wins outright.
	if _, headLive := m.Refs[head]; head != "" && headLive {
		if got != head {
			t.Fatalf("live head %q present but HeadForList = %q", head, got)
		}
		return
	}
	// Otherwise the selector ranges over branches only.
	switch {
	case bs.hasMain:
		if got != "refs/heads/main" {
			t.Fatalf("main present (no live head) but HeadForList = %q", got)
		}
	case bs.hasMaster:
		if got != "refs/heads/master" {
			t.Fatalf("master present (no live head/main) but HeadForList = %q", got)
		}
	case bs.hasBranch:
		if got != bs.minBranch {
			t.Fatalf("HeadForList = %q, want smallest branch %q", got, bs.minBranch)
		}
		for name := range m.Refs {
			if strings.HasPrefix(name, "refs/heads/") && got > name {
				t.Fatalf("HeadForList = %q is not the smallest branch; %q sorts before it", got, name)
			}
		}
	}
}

// assertPushInstall pins nextPushManifest's install contract: the generation is
// bumped by exactly one, the published ref set and head are installed wholesale
// (never merged with base), and version/repo identity carry forward unchanged.
func assertPushInstall(t *testing.T, man *manifest.Manifest, gen uint64, wantRefs map[string]string, head, repoID string) {
	t.Helper()
	if man.Generation != gen+1 {
		t.Fatalf("generation = %d, want %d", man.Generation, gen+1)
	}
	if !maps.Equal(man.Refs, wantRefs) {
		t.Fatalf("Refs = %v, want %v", man.Refs, wantRefs)
	}
	if man.Head != head {
		t.Fatalf("Head = %q, want %q", man.Head, head)
	}
	if man.Version != manifest.Version {
		t.Fatalf("version = %d, want %d", man.Version, manifest.Version)
	}
	if man.RepoID != repoID {
		t.Fatalf("RepoID = %q, want %q (must survive a push unchanged)", man.RepoID, repoID)
	}
}

// assertPackContinuity pins the pack-continuity invariant: every prior pack is
// retained in order, then the new pack is appended iff newID != "" (a push adds
// a pack, it never drops a live one, or clients lose access to its objects).
func assertPackContinuity(t *testing.T, man *manifest.Manifest, wantOldIDs []string, wantOldSizes []int64, newID string, newSize int64) {
	t.Helper()
	wantPackCount := len(wantOldIDs)
	if newID != "" {
		wantPackCount++
	}
	if len(man.Packs) != wantPackCount {
		t.Fatalf("got %d packs, want %d", len(man.Packs), wantPackCount)
	}
	for i := range wantOldIDs {
		if man.Packs[i].ID != wantOldIDs[i] || man.Packs[i].Size != wantOldSizes[i] {
			t.Fatalf("prior pack %d = {%q,%d}, want {%q,%d} (continuity)",
				i, man.Packs[i].ID, man.Packs[i].Size, wantOldIDs[i], wantOldSizes[i])
		}
	}
	if newID != "" {
		np := man.Packs[len(wantOldIDs)]
		if np.ID != newID || np.Size != newSize || len(np.Replaces) != 0 {
			t.Fatalf("appended pack = {%q,%d,replaces=%v}, want {%q,%d,nil}",
				np.ID, np.Size, np.Replaces, newID, newSize)
		}
	}
}

// assertBaseUnmutated pins nextPushManifest's isolation contract: scribbling the
// result must not corrupt the caller's base manifest, which pushOnce keeps using
// on a lost-CAS retry.
func assertBaseUnmutated(t *testing.T, base *manifest.Manifest, gen uint64, repoID string, snapRefs map[string]string, wantOldIDs []string) {
	t.Helper()
	if base.Generation != gen || base.RepoID != repoID {
		t.Fatalf("nextPushManifest mutated base meta")
	}
	if !maps.Equal(base.Refs, snapRefs) {
		t.Fatalf("nextPushManifest leaked into base.Refs: %v", base.Refs)
	}
	baseIDs := make([]string, 0, len(base.Packs))
	for _, p := range base.Packs {
		baseIDs = append(baseIDs, p.ID)
	}
	if !slices.Equal(baseIDs, wantOldIDs) {
		t.Fatalf("nextPushManifest mutated base packs: %v want %v", baseIDs, wantOldIDs)
	}
}

// assertRepackResult pins repackManifest's construction contract: the generation
// is bumped by exactly one, the pack set is the single merged pack (id/size
// verbatim) carrying every prior pack id in order as Replaces, and
// version/repo-id/head/refs carry forward unchanged.
func assertRepackResult(t *testing.T, man *manifest.Manifest, gen uint64, newID string, newSize int64, wantOldIDs []string, repoID, head string, snapRefs map[string]string) {
	t.Helper()
	if man.Generation != gen+1 {
		t.Fatalf("generation = %d, want %d", man.Generation, gen+1)
	}
	if len(man.Packs) != 1 {
		t.Fatalf("got %d packs, want exactly 1", len(man.Packs))
	}
	if man.Packs[0].ID != newID || man.Packs[0].Size != newSize {
		t.Fatalf("merged pack = {%q, %d}, want {%q, %d}",
			man.Packs[0].ID, man.Packs[0].Size, newID, newSize)
	}
	if !slices.Equal(man.Packs[0].Replaces, wantOldIDs) {
		t.Fatalf("Replaces = %v, want %v", man.Packs[0].Replaces, wantOldIDs)
	}
	if man.Version != manifest.Version {
		t.Fatalf("version = %d, want %d", man.Version, manifest.Version)
	}
	if man.RepoID != repoID {
		t.Fatalf("RepoID = %q, want %q (must survive a repack unchanged)", man.RepoID, repoID)
	}
	if man.Head != head {
		t.Fatalf("Head = %q, want %q", man.Head, head)
	}
	if !maps.Equal(man.Refs, snapRefs) {
		t.Fatalf("Refs = %v, want %v", man.Refs, snapRefs)
	}
}

// assertCurUnmutated pins repackManifest's isolation contract: scribbling the
// result must not corrupt cur's manifest, which repackOnce keeps using on a
// lost-CAS retry.
func assertCurUnmutated(t *testing.T, cur *RemoteState, gen uint64, repoID, head string, snapRefs map[string]string, wantOldIDs []string) {
	t.Helper()
	if cur.Manifest.Generation != gen {
		t.Fatalf("repackManifest mutated cur generation: %d != %d", cur.Manifest.Generation, gen)
	}
	if cur.Manifest.RepoID != repoID || cur.Manifest.Head != head {
		t.Fatalf("repackManifest mutated cur meta")
	}
	if !maps.Equal(cur.Manifest.Refs, snapRefs) {
		t.Fatalf("repackManifest leaked into cur.Refs: %v", cur.Manifest.Refs)
	}
	curOldIDs := make([]string, 0, len(cur.Manifest.Packs))
	for _, p := range cur.Manifest.Packs {
		curOldIDs = append(curOldIDs, p.ID)
	}
	if !slices.Equal(curOldIDs, wantOldIDs) {
		t.Fatalf("repackManifest mutated cur packs: %v want %v", curOldIDs, wantOldIDs)
	}
}

// assertConsolidatedShape pins consolidatedPacks' shape: exactly the survivors
// (verbatim, in order) followed by the one merged pack, whose id/size are
// verbatim and whose Replaces is the victim list in order with no drop/dup/reorder.
func assertConsolidatedShape(t *testing.T, got, wantSurvivors []manifest.Pack, mergedID string, mergedSize int64, victimIDs []string) {
	t.Helper()
	if len(got) != len(wantSurvivors)+1 {
		t.Fatalf("got %d packs, want %d survivors + 1 merged", len(got), len(wantSurvivors))
	}
	for i := range wantSurvivors {
		if !packFieldsEqual(got[i], wantSurvivors[i]) {
			t.Fatalf("survivor %d = %+v, want %+v", i, got[i], wantSurvivors[i])
		}
	}
	merged := got[len(got)-1]
	if merged.ID != mergedID || merged.Size != mergedSize {
		t.Fatalf("merged pack = {%q,%d}, want {%q,%d}", merged.ID, merged.Size, mergedID, mergedSize)
	}
	if !slices.Equal(merged.Replaces, victimIDs) {
		t.Fatalf("merged Replaces = %v, want %v", merged.Replaces, victimIDs)
	}
}

// assertConsolidationComplete pins the load-bearing consolidation harm statement:
// every live pack is either retained as a survivor or declared superseded in the
// merged pack's Replaces (a live pack that vanished unlisted would be lost to a
// client that had not applied it -- it would never re-download it), and dually no
// survivor is itself a victim.
func assertConsolidationComplete(t *testing.T, got, packs []manifest.Pack, victimIDs []string) {
	t.Helper()
	survivors := got[:len(got)-1]
	merged := got[len(got)-1]
	for _, p := range packs {
		retained := slices.ContainsFunc(survivors, func(s manifest.Pack) bool { return s.ID == p.ID })
		if !retained && !slices.Contains(merged.Replaces, p.ID) {
			t.Fatalf("live pack %q neither retained nor superseded in Replaces", p.ID)
		}
	}
	for _, s := range survivors {
		if slices.Contains(victimIDs, s.ID) {
			t.Fatalf("victim pack %q survived the consolidation", s.ID)
		}
	}
}

// assertConsolidatedNoMutation pins that consolidatedPacks reads its inputs and
// builds a fresh slice, mutating neither packs nor victimIDs (applyConsolidation
// hands it the live plan.man.Packs).
func assertConsolidatedNoMutation(t *testing.T, packs, packsSnap []manifest.Pack, victimIDs, victimSnap []string) {
	t.Helper()
	if len(packs) != len(packsSnap) {
		t.Fatalf("packs slice length changed: %d != %d", len(packs), len(packsSnap))
	}
	for i := range packs {
		if !packFieldsEqual(packs[i], packsSnap[i]) {
			t.Fatalf("packs[%d] mutated", i)
		}
	}
	if !slices.Equal(victimIDs, victimSnap) {
		t.Fatalf("victimIDs mutated: %v want %v", victimIDs, victimSnap)
	}
}

// assertCanMarkVerdict pins canMarkConsolidated's verdict: victimIDs are the
// victim ids in order, and canMark holds IFF every victim is covered -- already
// applied or the not-yet-pushed pack -- re-derived here as a union membership
// test (a different shape than the implementation's per-victim flip). The
// one-sided floor is the load-bearing harm statement: a canMark=true with a
// never-applied, non-pushed victim would mark the merged pack applied while its
// objects are absent locally, skipping a needed download forever.
func assertCanMarkVerdict(t *testing.T, gotIDs []string, gotCanMark bool, victims []manifest.Pack, notYetPushedID string, applied map[string]bool) {
	t.Helper()
	wantIDs := make([]string, 0, len(victims))
	for _, v := range victims {
		wantIDs = append(wantIDs, v.ID)
	}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("victimIDs = %v, want %v", gotIDs, wantIDs)
	}

	covered := maps.Clone(applied)
	covered[notYetPushedID] = true
	wantCanMark := true
	for _, v := range victims {
		if !covered[v.ID] {
			wantCanMark = false
			break
		}
	}
	if gotCanMark != wantCanMark {
		t.Fatalf("canMark = %v, want %v (victims=%v notYet=%q applied=%v)",
			gotCanMark, wantCanMark, wantIDs, notYetPushedID, applied)
	}

	if gotCanMark {
		for _, v := range victims {
			if v.ID != notYetPushedID && !applied[v.ID] {
				t.Fatalf("canMark=true but victim %q is neither the not-yet-pushed pack nor applied", v.ID)
			}
		}
	}
}

// assertCanMarkNoMutation pins that canMarkConsolidated reads applied and victims
// and builds a fresh slice, mutating neither. (manifest.Pack carries a slice
// field so it is not comparable; compare the fields this target sets.)
func assertCanMarkNoMutation(t *testing.T, victims, victimSnap []manifest.Pack, applied, appliedSnap map[string]bool) {
	t.Helper()
	if len(victims) != len(victimSnap) {
		t.Fatalf("victims slice length changed: %d != %d", len(victims), len(victimSnap))
	}
	for i := range victims {
		if victims[i].ID != victimSnap[i].ID || victims[i].Size != victimSnap[i].Size {
			t.Fatalf("victims[%d] mutated", i)
		}
	}
	if !maps.Equal(applied, appliedSnap) {
		t.Fatalf("applied map mutated")
	}
}

// assertDeletePlan pins planRefUpdates' delete authorization and projection: one
// result per update in order (each reporting its own Dst), a delete accepted iff
// its target is present in the ORIGINAL remote set (and then removed from the
// projected ref set) else rejected with "remote ref does not exist", no pack want
// from any delete, and the accepted count and projected ref set matching the
// independently re-derived oracle.
func assertDeletePlan(t *testing.T, results []RefResult, newRefs map[string]string, wants []string, accepted int, updates []RefUpdate, before map[string]string) {
	t.Helper()
	if len(results) != len(updates) {
		t.Fatalf("got %d results, want %d", len(results), len(updates))
	}

	wantAccepted := 0
	wantNew := maps.Clone(before)
	for i, u := range updates {
		_, present := before[u.Dst]
		if results[i].Dst != u.Dst {
			t.Fatalf("results[%d].Dst = %q, want %q", i, results[i].Dst, u.Dst)
		}
		if present {
			wantAccepted++
			delete(wantNew, u.Dst)
			if results[i].Err != "" {
				t.Fatalf("accepted delete of %q reported Err %q, want empty", u.Dst, results[i].Err)
			}
		} else if results[i].Err != "remote ref does not exist" {
			t.Fatalf("rejected delete of %q reported Err %q, want %q",
				u.Dst, results[i].Err, "remote ref does not exist")
		}
	}

	if accepted != wantAccepted {
		t.Fatalf("accepted = %d, want %d", accepted, wantAccepted)
	}
	if len(wants) != 0 {
		t.Fatalf("deletes produced %d pack wants, want 0: %v", len(wants), wants)
	}
	if !maps.Equal(newRefs, wantNew) {
		t.Fatalf("newRefs = %v, want %v", newRefs, wantNew)
	}
}

// assertSkippableSafety pins packSkippable's composition and one-sided safety: the
// gate is exactly "covered OR local closure complete"; a skip while the closure is
// NOT complete is justified only by full replaces cover (every superseded pack
// applied); and a pack with no predecessors is never covered, so its gate reduces
// to the closure verdict alone.
func assertSkippableSafety(t *testing.T, got, covered, closureResult bool, replaces []string, appliedSet map[string]bool) {
	t.Helper()
	if want := covered || closureResult; got != want {
		t.Fatalf("packSkippable = %v, want %v (covered=%v closure=%v)",
			got, want, covered, closureResult)
	}
	if got && !closureResult {
		if len(replaces) == 0 {
			t.Fatalf("skipped a pack with no predecessors and no local closure")
		}
		for _, r := range replaces {
			if !appliedSet[r] {
				t.Fatalf("skipped a pack while predecessor %q is not applied", r)
			}
		}
	}
	if len(replaces) == 0 {
		if covered {
			t.Fatalf("replacesCovered = true for a pack with no predecessors")
		}
		if got != closureResult {
			t.Fatalf("empty-replaces gate = %v, want closure %v", got, closureResult)
		}
	}
}

// assertSkippableMonotonic pins packSkippable's monotonicity toward full cover:
// marking EVERY predecessor applied can only make a non-empty pack covered, never
// un-cover one already covered.
func assertSkippableMonotonic(t *testing.T, p manifest.Pack, replaces []string, covered bool) {
	t.Helper()
	full := map[string]bool{}
	for _, r := range replaces {
		full[r] = true
	}
	fullCovered := replacesCovered(p, full)
	if fullCovered != (len(replaces) > 0) {
		t.Fatalf("replacesCovered with all applied = %v, want %v", fullCovered, len(replaces) > 0)
	}
	if covered && !fullCovered {
		t.Fatalf("covered under a subset but not under the full applied set")
	}
}

// assertSelectHeadSafety pins selectManifestHead's membership and provenance: a
// non-empty head is always a ref the manifest carries (the dangling-HEAD guard),
// and the result is only ever one of its two candidate inputs or empty.
func assertSelectHeadSafety(t *testing.T, got, local, prevHead string, hasPrev bool, refs map[string]string) {
	t.Helper()
	if got != "" {
		if _, ok := refs[got]; !ok {
			t.Fatalf("selectManifestHead = %q, which is not in the ref set %v", got, refs)
		}
	}
	if got != "" && got != local && !(hasPrev && got == prevHead) {
		t.Fatalf("selectManifestHead = %q, neither local %q nor prev head %q", got, local, prevHead)
	}
}

// assertSelectHeadCascade pins selectManifestHead's priority cascade: the local
// HEAD branch wins outright (even when prev is also usable), else the prev head is
// the fallback, else there is no head; and emptiness holds iff no candidate is
// usable.
func assertSelectHeadCascade(t *testing.T, got, local, prevHead string, localUsable, prevUsable bool) {
	t.Helper()
	switch {
	case localUsable:
		if got != local {
			t.Fatalf("local %q is usable but selectManifestHead = %q", local, got)
		}
	case prevUsable:
		if got != prevHead {
			t.Fatalf("local unusable and prev %q usable but selectManifestHead = %q", prevHead, got)
		}
	default:
		if got != "" {
			t.Fatalf("no usable candidate but selectManifestHead = %q", got)
		}
	}
	if (got == "") == (localUsable || prevUsable) {
		t.Fatalf("got = %q but localUsable=%v prevUsable=%v", got, localUsable, prevUsable)
	}
}
