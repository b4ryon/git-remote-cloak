// Package config reads cloak's per-repo settings from the cloak.* git
// config namespace, applying documented defaults.
package config

import (
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
}

// Defaults returns the documented default configuration.
func Defaults() Config {
	return Config{
		KeyRef:          keystore.DefaultRef(),
		GeometricFactor: 2,
		PushRetries:     5,
		Branch:          "cloak",
		LogLevel:        "info",
	}
}

// Load reads cloak.* from the repository at gitDir (plus global config).
func Load(g *gitx.G, gitDir string) (Config, error) {
	c := Defaults()
	out, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "config", "--get-regexp", `^cloak\.`)
	if err != nil {
		if ge, ok := err.(*gitx.GitError); ok && ge.ExitCode == 1 {
			return c, nil // no cloak.* keys set
		}
		return c, err
	}
	applyConfigLines(&c, out)
	return c, nil
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
	}
}

// setIfValidInt parses val as a base-10 int and stores it in *dst only
// when it parses and is at least min, leaving the existing default otherwise.
func setIfValidInt(dst *int, val string, min int) {
	if n, err := strconv.Atoi(val); err == nil && n >= min {
		*dst = n
	}
}
