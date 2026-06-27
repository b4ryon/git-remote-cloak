// Package config reads cloak's per-repo settings from the cloak.* git
// config namespace, applying documented defaults.
package config

import (
	"errors"
	"strconv"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// Config holds the resolved cloak.* settings.
type Config struct {
	// KeyRef locates the master key ("file:<path>" or "keychain:<name>").
	KeyRef string
	// GeometricFactor is the consolidation factor; 0 disables auto-consolidation.
	GeometricFactor int
	// PushRetries caps CAS retry attempts.
	PushRetries int
	// Branch is the backend branch name on the host.
	Branch string
	// LogLevel is the per-repo file log level (CLOAK_LOG env overrides).
	LogLevel string
	// MaxPackBytes is the largest encrypted pack (one host file) cloak will
	// publish; a build that would exceed it is refused before upload. 0 disables
	// the check. Defaults to GitHub's per-file hard cap (100 MiB).
	MaxPackBytes int64
}

// Defaults returns the documented default configuration.
func Defaults() Config {
	return Config{
		KeyRef:          keystore.DefaultRef(),
		GeometricFactor: 2,
		PushRetries:     5,
		Branch:          "cloak",
		LogLevel:        "info",
		MaxPackBytes:    100 << 20, // 100 MiB: GitHub's per-file hard cap
	}
}

// Load reads cloak.* from the repository at gitDir (plus global config).
func Load(g *gitx.G, gitDir string) (Config, error) {
	c := Defaults()
	out, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "config", "--get-regexp", `^cloak\.`)
	if err != nil {
		if isNoMatchingKeys(err) {
			return c, nil // no cloak.* keys set
		}
		return c, err
	}
	applyConfigLines(&c, out)
	return c, nil
}

// isNoMatchingKeys reports whether err is git config's "no key matched the
// pattern" outcome: a *gitx.GitError with exit code 1. Every other exit code is
// a real failure git config could not complete, which Load must surface rather
// than silently returning defaults. The detection goes through errors.As (not a
// direct type assertion) so it still recognizes the sentinel if the error is
// ever wrapped further up the call chain, matching the errors.As idiom the rest
// of the codebase already uses for typed git errors; an unrecognized error type
// falls through and the failure is reported.
func isNoMatchingKeys(err error) bool {
	var ge *gitx.GitError
	return errors.As(err, &ge) && ge.ExitCode == 1
}

// applyConfigLines parses `git config --get-regexp` output (one "key value"
// line per setting) and applies each recognized cloak.* setting to c,
// skipping blank and value-less lines.
func applyConfigLines(c *Config, out string) {
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		key, val, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		applyConfigSetting(c, strings.ToLower(key), val)
	}
}

// applyConfigSetting applies a single cloak.* setting (key already
// lower-cased, val the raw value) to c, ignoring unknown keys and
// out-of-range numeric values so the documented default survives.
func applyConfigSetting(c *Config, key, val string) {
	switch key {
	case "cloak.keyref":
		c.KeyRef = val
	case "cloak.geometricfactor":
		setIfValidInt(&c.GeometricFactor, val, 0)
	case "cloak.pushretries":
		setIfValidInt(&c.PushRetries, val, 1)
	case "cloak.branch":
		if val != "" {
			c.Branch = val
		}
	case "cloak.loglevel":
		c.LogLevel = val
	case "cloak.maxpackbytes":
		setIfValidInt64(&c.MaxPackBytes, val, 0)
	}
}

// setIfValidInt parses val as a base-10 int and stores it in *dst only
// when it parses and is at least min, leaving the existing default otherwise.
func setIfValidInt(dst *int, val string, min int) {
	if n, err := strconv.Atoi(val); err == nil && n >= min {
		*dst = n
	}
}

// setIfValidInt64 parses val as a base-10 int64 and stores it in *dst only when
// it parses and is at least min, leaving the existing default otherwise. The
// int64 sibling of setIfValidInt, for byte-count settings whose values exceed
// the int range on 32-bit platforms.
func setIfValidInt64(dst *int64, val string, min int64) {
	if n, err := strconv.ParseInt(val, 10, 64); err == nil && n >= min {
		*dst = n
	}
}
