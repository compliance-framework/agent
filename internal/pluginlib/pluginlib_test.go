package pluginlib

import (
	"os"
	"path/filepath"
	"testing"

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
