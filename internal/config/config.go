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
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		key, val, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		switch strings.ToLower(key) {
		case "cloak.keyref":
			c.KeyRef = val
		case "cloak.geometricfactor":
			if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				c.GeometricFactor = n
			}
		case "cloak.pushretries":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				c.PushRetries = n
			}
		case "cloak.branch":
			if val != "" {
				c.Branch = val
			}
		case "cloak.loglevel":
			c.LogLevel = val
		}
	}
	return c, nil
}
