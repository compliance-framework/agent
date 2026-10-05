// Package pluginlib reads which version of this module (the agent library) a plugin binary
// was built with (R76). The config report lists it per plugin as diagnostics.
//
// Plugins evaluate policies with the policy-manager they embed, so how a plugin evaluates a
// policy depends on the agent library it was compiled against, not on the running agent.
// The version comes from the binary's Go build info (debug/buildinfo), so the plugin is never
// started to find out.
package pluginlib

import (
	"debug/buildinfo"
	"os"
	"sync"
	"time"
)

// AgentModule is the module path plugins import for runner and policy-manager.
const AgentModule = "github.com/compliance-framework/agent"

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
