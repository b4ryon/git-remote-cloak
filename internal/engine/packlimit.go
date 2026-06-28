// Pre-flight pack-size guard (Tier 1b): cloak stores each encrypted pack as one
// file on the host, and hosts cap per-file size (GitHub: 100 MiB). Before any
// upload, the engine checks a freshly built pack's ciphertext size against
// cloak.maxPackBytes and, when it would not fit, refuses with a clear error that
// names the largest underlying files so the user knows what to shrink. The check
// is local-only and changes no on-disk/on-wire/crypto format; it reads the
// manifest's existing Pack.Size for the consolidation prediction. The
// complementary host-rejection backstop (Tier 1a) lives in internal/backend.
package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

// maxReportedFiles caps how many of the largest files the over-limit error
// lists, so the message stays readable on a pack with thousands of objects.
const maxReportedFiles = 5

// objInfo is one file's path and uncompressed object size, for the over-limit
// report.
type objInfo struct {
	path string
	size int64
}

// checkPackLimit refuses a pack whose ciphertext size exceeds cloak.maxPackBytes
// (0 disables the check). op names the operation for the error ("push" /
// "repack"). On a violation it builds a TooLarge error naming the largest files
// in the pack (enumerated from wants minus haves in the local repository);
// otherwise it returns nil. The size limit is intrinsic to the pack ciphertext,
// while the file list is best-effort context: if git enumeration fails the error
// still reports the size, just without the per-file breakdown.
func (e *Engine) checkPackLimit(op string, size int64, wants, haves []string) error {
	if e.Cfg.MaxPackBytes <= 0 || size <= e.Cfg.MaxPackBytes {
		return nil
	}
	return packTooLargeErr(op, size, e.Cfg.MaxPackBytes, e.largestObjects(wants, haves))
}

// consolidationWouldExceed reports whether merging victims into one pack would
// exceed cloak.maxPackBytes, predicted from the manifest's recorded ciphertext
// sizes (no download or packing). The merged pack is at most the sum of the
// victim sizes (re-delta can only shrink it), so this never under-predicts a
// genuine overflow; it errs toward skipping a consolidation that might have just
// fit, which is the safe direction (skipping only leaves more, smaller packs).
func (e *Engine) consolidationWouldExceed(victims []manifest.Pack) bool {
	return e.Cfg.MaxPackBytes > 0 && sumPackSizes(victims) > e.Cfg.MaxPackBytes
}

// sumPackSizes totals the ciphertext sizes of packs. Sizes are non-negative and
// capped (manifest.Validate), and maxPacks*maxPackSize stays below 2^63, so the
// int64 sum cannot overflow over any AEAD-valid manifest.
func sumPackSizes(packs []manifest.Pack) int64 {
	var total int64
	for _, p := range packs {
		total += p.Size
	}
	return total
}

// splitBudget returns the plaintext --max-pack-size to hand `git pack-objects`
// when splitting an over-limit push into multiple packs, or 0 when the limit is
// too small (or disabled) to split usefully. age does not compress, so a pack's
// ciphertext is its plaintext size plus a tiny near-constant overhead (an ~200 B
// header and a 16 B tag per 64 KiB chunk, ~0.025%); we subtract a margin of
// limit/2048 + 4 KiB (well above that overhead, also absorbing git's approximate
// enforcement) so each encrypted pack stays under limit. git itself floors
// --max-pack-size at 1 MiB, so a budget below that returns 0: the caller then
// keeps a single pack and the post-build size check reports it if it still does
// not fit (a sub-MiB host limit is pathological and cannot be split anyway).
func splitBudget(limit int64) int64 {
	if limit <= 0 {
		return 0
	}
	budget := limit - (limit/2048 + 4096)
	if budget < 1<<20 {
		return 0
	}
	return budget
}

// pushFileTooLargeErr builds the push-path TooLarge error for a single file
// whose encrypted pack (encSize) exceeds the host's per-file limit -- the one
// case bin-packing cannot fix, because git cannot split a single object across
// packs. file names the offending path ("" when git enumeration failed). The
// wording is written end-to-end here (via cloakerr.Newmsg) so it stays short and
// actionable; it keeps the TooLarge Kind for classification.
func pushFileTooLargeErr(encSize, limit int64, file string) error {
	if file == "" {
		file = "(one file)"
	}
	msg := fmt.Sprintf("cloak: push blocked - one file exceeds the host's per-file limit.\n"+
		"  %s   %s encrypted  (limit %s)\n"+
		"  The host keeps each pack as one file (GitHub caps files at 100 MiB).\n"+
		"  Fix: remove it, move it to git-lfs, or raise\n"+
		"       cloak.maxPackBytes  (git config cloak.maxPackBytes <bytes>; 0 = off)",
		file, humanBytes(encSize), humanBytes(limit))
	return cloakerr.Newmsg(cloakerr.TooLarge, msg)
}

// offendingFile names the worktree path of the largest blob stored in the
// over-limit split pack at plainPackPath (read from the pack itself via
// verify-pack, then mapped to a path through the pushed objects). Best-effort:
// any git failure yields "", and the caller falls back to a generic noun.
func (e *Engine) offendingFile(plainPackPath string, wants []string) string {
	out, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir}, "verify-pack", "-v", plainPackPath)
	if err != nil {
		return ""
	}
	// verify-pack -v lines: "<oid> <type> <size> <size-in-pack> <offset> [depth base]".
	var bestOID string
	var bestPacked int64 = -1
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "blob" || !manifest.IsLowerHex(f[0], 40) {
			continue
		}
		packed, perr := strconv.ParseInt(f[3], 10, 64)
		if perr != nil {
			continue
		}
		if packed > bestPacked {
			bestPacked, bestOID = packed, f[0]
		}
	}
	if bestOID == "" {
		return ""
	}
	return e.objectPaths(wants)[bestOID]
}

// objectPaths maps object id -> worktree path for the objects reachable from
// wants in the local repository (commits, which have no path, are dropped by
// parseObjectPaths). Best-effort: a git failure yields nil.
func (e *Engine) objectPaths(wants []string) map[string]string {
	args := append([]string{"rev-list", "--objects"}, wants...)
	out, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir}, args...)
	if err != nil {
		return nil
	}
	return parseObjectPaths(out)
}

// largestObjects returns the largest blobs (by uncompressed size, descending,
// capped at maxReportedFiles) among the objects a pack would carry: those
// reachable from wants but not from haves in the local repository. Best-effort:
// any git failure yields a nil slice, so the caller's error still reports the
// pack size without a per-file breakdown. haves may be empty (a full repack).
func (e *Engine) largestObjects(wants, haves []string) []objInfo {
	args := append([]string{"rev-list", "--objects"}, wants...)
	if len(haves) > 0 {
		args = append(args, "--not")
		args = append(args, haves...)
	}
	out, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir}, args...)
	if err != nil {
		return nil
	}
	paths := parseObjectPaths(out)
	if len(paths) == 0 {
		return nil
	}
	var stdin strings.Builder
	for oid := range paths {
		fmt.Fprintln(&stdin, oid)
	}
	sizeOut, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir, Stdin: strings.NewReader(stdin.String())},
		"cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	if err != nil {
		return nil
	}
	infos := combineBlobInfo(paths, sizeOut)
	sort.Slice(infos, func(i, j int) bool { return infos[i].size > infos[j].size })
	if len(infos) > maxReportedFiles {
		infos = infos[:maxReportedFiles]
	}
	return infos
}

// parseObjectPaths maps object id -> path from `git rev-list --objects` output.
// Each line is "<oid>" (commits, no path) or "<oid> <path>" (trees and blobs);
// only the lines that carry a path are kept (a path may itself contain spaces,
// so everything after the first space is the path). Pure, so it is fuzzable
// without a git host.
func parseObjectPaths(revListOut string) map[string]string {
	paths := map[string]string{}
	for _, line := range strings.Split(revListOut, "\n") {
		oid, path, found := strings.Cut(line, " ")
		if found && path != "" && manifest.IsLowerHex(oid, 40) {
			paths[oid] = path
		}
	}
	return paths
}

// combineBlobInfo joins the oid->path map with `git cat-file --batch-check`
// output ("<oid> <type> <size>" per line) into the blob entries: it keeps only
// lines whose type is "blob" and whose oid has a path, attaching the path and
// parsed size. Non-blob, malformed, or "missing" lines are skipped. Pure, so it
// is fuzzable without a git host.
func combineBlobInfo(paths map[string]string, catFileOut string) []objInfo {
	var infos []objInfo
	for _, line := range strings.Split(catFileOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[1] != "blob" {
			continue
		}
		path, ok := paths[fields[0]]
		if !ok {
			continue
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		infos = append(infos, objInfo{path: path, size: size})
	}
	return infos
}

// packTooLargeErr builds the TooLarge error for an over-limit pack: a headline
// stating the encrypted pack size against the limit, and a hint listing the
// largest files, flagging any single file that alone exceeds the limit (which no
// pack split can fix), and giving the remediation options.
func packTooLargeErr(op string, size, limit int64, biggest []objInfo) error {
	return cloakerr.Newfh(cloakerr.TooLarge, op, packTooLargeHint(biggest, limit),
		"encrypted pack is %s, which exceeds the limit of %s (cloak.maxPackBytes); the host stores each pack as a single file (GitHub caps files at 100 MiB)",
		humanBytes(size), humanBytes(limit))
}

// packTooLargeHint renders the multi-line hint: the largest files (uncompressed
// sizes, as guidance) and the remediation. When git could not enumerate the
// files (biggest is empty) it gives the remediation alone.
func packTooLargeHint(biggest []objInfo, limit int64) string {
	var b strings.Builder
	if len(biggest) > 0 {
		b.WriteString("largest files in this pack (uncompressed):")
		for _, o := range biggest {
			fmt.Fprintf(&b, "\n    - %s (%s)", o.path, humanBytes(o.size))
		}
		if biggest[0].size > limit {
			fmt.Fprintf(&b, "\n  %q alone exceeds the limit and cannot be stored as a single pack; remove it or use git-lfs on the host", biggest[0].path)
		}
		b.WriteString("\n  ")
	}
	b.WriteString("shrink or remove the large file(s) and re-commit, or raise `git config cloak.maxPackBytes <bytes>` (set 0 to disable this check)")
	return b.String()
}

// humanBytes renders a byte count as MiB with one decimal for readability, or as
// a raw byte count below 1 MiB.
func humanBytes(n int64) string {
	const mib = 1 << 20
	if n >= mib {
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(mib))
	}
	return fmt.Sprintf("%d bytes", n)
}
