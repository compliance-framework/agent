// Package pluginlib reads which version of this module (the agent library) a plugin binary
// was built with, and decides what the plugin supports (R76).
//
// Plugins evaluate policies with the policy-manager they embed, so what a plugin can do with
// a policy depends on the agent library it was compiled against, not on the running agent.
// The version comes from the binary's Go build info (debug/buildinfo), so the plugin is never
// started to find out.
package pluginlib

import (
	"debug/buildinfo"
	"os"
	"sync"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// AgentModule is the module path plugins import for runner and policy-manager.
const AgentModule = "github.com/compliance-framework/agent"

// Minimum agent library versions.
const (
	// MinViolationSet is the first agent library whose policy-manager accepts violation as a
	// set (`violation contains {...}`, agent#86). Older plugins expect an object
	// (`violation[{...}] if { ... }`) and crash on a set.
	MinViolationSet = "v0.7.1"
	// MinPolicyID is the first agent library release whose policy-manager seeds evidence
	// with an authored policy_id (R74): agent#95 ships in v0.9.0 (v0.8.0 and v0.8.1 were
	// released without it). Older plugins ignore policy_id. The minimum is the final
	// release, so v0.9.0 release candidates and pseudo-versions based on them are older
	// (AtLeast). It also covers MinViolationSet.
	//
	// Update before tagging if agent#95 ships in a different release.
	MinPolicyID = "v0.9.0"
)

// Version returns the version of AgentModule the plugin binary at path was built with, or ""
// when it is unknown: the file has no Go build info, does not depend on AgentModule (a
// non-Go or unrelated binary), or replaces it (a local build, where the version says nothing
// about the code). An error is returned only when the file cannot be read as a Go binary.
func Version(path string) (string, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, dep := range info.Deps {
		if dep.Path != AgentModule {
			continue
		}
		if dep.Replace != nil || dep.Version == "(devel)" {
			return "", nil
		}
		return dep.Version, nil
	}
	return "", nil
}

// AtLeast reports whether version is min or later. known is false when version is not a
// version that can be compared ("" for unknown, "(devel)", a pseudo-version with no tag
// before it): then ok is false too. A pseudo-version counts as the tagged version it was
// built after (v0.7.2-0.2026…-abc is v0.7.1 plus unreleased commits, which may not include
// what min added). Versions compare as semver, so pre-releases of min are older than min
// (v0.9.0-rc1 < v0.9.0): a release candidate cut before a feature landed does not have it.
func AtLeast(version, min string) (ok, known bool) {
	base := version
	if module.IsPseudoVersion(version) {
		var err error
		if base, err = module.PseudoVersionBase(version); err != nil || base == "" {
			return false, false
		}
	}
	if !semver.IsValid(base) {
		return false, false
	}
	return semver.Compare(base, min) >= 0, true
}

// Cache memoizes Version per binary. A binary is identified by its path, size and
// modification time, so a plugin replaced in place is read again. It is safe for concurrent
// use.
type Cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	size    int64
	modTime time.Time
	version string
	err     error
}

// cacheLimit bounds the cache; plugins are few, so it is only a safety net.
const cacheLimit = 256

// Version is the package-level Version, memoized.
func (c *Cache) Version(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	if e, ok := c.entries[path]; ok && e.size == st.Size() && e.modTime.Equal(st.ModTime()) {
		c.mu.Unlock()
		return e.version, e.err
	}
	c.mu.Unlock()

	version, err := Version(path)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= cacheLimit {
		c.entries = map[string]cacheEntry{}
	}
	c.entries[path] = cacheEntry{size: st.Size(), modTime: st.ModTime(), version: version, err: err}
	return version, err
}
