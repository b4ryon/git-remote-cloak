// Package version exposes the build version, stamped via -ldflags at
// build/release time and reported by `git cloak version`.
package version

import "runtime/debug"

// Version is overridden at build time with
// -ldflags "-X github.com/b4ryon/git-remote-cloak/internal/version.Version=v0.1.0".
// It MUST stay declared as an uninitialized/constant string for -X to take
// effect; do not initialize it with a function call. When left empty (a plain
// `go build`/`go install` with no ldflags), String() falls back to the build
// info so the reported version is still meaningful rather than "dev".
var Version = ""

// String returns the build version: the -ldflags value when set, otherwise the
// module version (e.g. from `go install ...@v0.1.4`) or the VCS revision
// recorded in the build info, or "unknown" as a last resort.
func String() string {
	if Version != "" {
		return Version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	if rev := vcsRevision(bi.Settings); rev != "" {
		return rev
	}
	return "unknown"
}

// vcsRevision extracts the VCS revision from build settings, truncated to 12
// characters and suffixed with "-dirty" when the working tree was modified at
// build time. It returns "" when no vcs.revision is recorded.
func vcsRevision(settings []debug.BuildSetting) string {
	var rev, dirty string
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return ""
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev + dirty
}
