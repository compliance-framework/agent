package pluginlib

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	// The test binary is built from this module itself, so it does not depend on it.
	self, err := os.Executable()
	require.NoError(t, err)
	version, err := Version(self)
	require.NoError(t, err)
	assert.Empty(t, version)

	notGo := filepath.Join(t.TempDir(), "plugin")
	require.NoError(t, os.WriteFile(notGo, []byte("#!/bin/sh\necho hi\n"), 0o755))
	_, err = Version(notGo)
	assert.Error(t, err)

	var cache Cache
	version, err = cache.Version(self)
	require.NoError(t, err)
	assert.Empty(t, version)
	_, err = cache.Version(notGo)
	assert.Error(t, err)
	_, err = cache.Version(filepath.Join(t.TempDir(), "missing"))
	assert.Error(t, err)
}

func TestVersionFromInfo(t *testing.T) {
	other := &debug.Module{Path: "github.com/hashicorp/go-plugin", Version: "v1.6.0"}
	for _, tc := range []struct {
		name string
		deps []*debug.Module
		want string
	}{
		{"released version", []*debug.Module{other, {Path: AgentModule, Version: "v0.5.0"}}, "v0.5.0"},
		{"pseudo-version", []*debug.Module{{Path: AgentModule, Version: "v0.5.1-0.20260101000000-abcdef123456"}}, "v0.5.1-0.20260101000000-abcdef123456"},
		{"replaced", []*debug.Module{{Path: AgentModule, Version: "v0.5.0", Replace: &debug.Module{Path: "../agent"}}}, ""},
		{"devel", []*debug.Module{{Path: AgentModule, Version: "(devel)"}}, ""},
		{"absent", []*debug.Module{other}, ""},
		{"no deps", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, versionFromInfo(&debug.BuildInfo{Deps: tc.deps}))
		})
	}
}

func TestCacheRereadsAChangedBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o755))
	reads := 0
	cache := Cache{read: func(string) (string, error) {
		reads++
		return fmt.Sprintf("v0.%d.0", reads), nil
	}}

	version, err := cache.Version(path)
	require.NoError(t, err)
	assert.Equal(t, "v0.1.0", version)
	version, err = cache.Version(path)
	require.NoError(t, err)
	assert.Equal(t, "v0.1.0", version, "an unchanged binary is not read again")
	assert.Equal(t, 1, reads)

	require.NoError(t, os.WriteFile(path, []byte("v2 longer"), 0o755))
	version, err = cache.Version(path)
	require.NoError(t, err)
	assert.Equal(t, "v0.2.0", version, "a new size is read again")

	st, err := os.Stat(path)
	require.NoError(t, err)
	later := st.ModTime().Add(time.Minute)
	require.NoError(t, os.Chtimes(path, later, later))
	version, err = cache.Version(path)
	require.NoError(t, err)
	assert.Equal(t, "v0.3.0", version, "a new modification time is read again")
	assert.Equal(t, 3, reads)
}
