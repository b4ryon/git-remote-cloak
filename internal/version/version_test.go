// Tests for the version package: the VCS-revision build-setting parser and the
// ldflags-override fast path of String().
package version

import (
	"runtime/debug"
	"testing"
)

func TestVcsRevision(t *testing.T) {
	cases := []struct {
		name     string
		settings []debug.BuildSetting
		want     string
	}{
		{"none", nil, ""},
		{"no revision key", []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}, ""},
		{"clean short", []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}}, "abc123"},
		{"clean long truncates", []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef"}}, "0123456789ab"},
		{"dirty", []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}, {Key: "vcs.modified", Value: "true"}}, "abc123-dirty"},
		{"modified false stays clean", []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}, {Key: "vcs.modified", Value: "false"}}, "abc123"},
		{"dirty long truncates before suffix", []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef"}, {Key: "vcs.modified", Value: "true"}}, "0123456789ab-dirty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := vcsRevision(tc.settings); got != tc.want {
				t.Errorf("vcsRevision() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStringUsesLdflagsVersion(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Errorf("String() = %q, want %q", got, "v1.2.3")
	}
}
