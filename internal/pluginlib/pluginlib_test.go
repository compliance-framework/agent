package pluginlib

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAtLeast(t *testing.T) {
	cases := []struct {
		version, min string
		ok, known    bool
	}{
		{"v0.7.1", MinViolationSet, true, true},
		{"v0.7.2", MinViolationSet, true, true},
		{"v0.7.0", MinViolationSet, false, true},
		{"v0.1.9", MinViolationSet, false, true},
		{"v0.1.9-0.20250101000000-abcdefabcdef", MinViolationSet, false, true}, // after v0.1.8
		{"v0.7.2-0.20260601000000-abcdefabcdef", MinViolationSet, true, true},  // after v0.7.1
		{"v0.7.1-0.20260501000000-abcdefabcdef", MinViolationSet, false, true}, // after v0.7.0, before v0.7.1
		{"v0.8.0-rc4", MinInlinePolicy, false, true},
		{"v0.8.0", MinInlinePolicy, false, true},
		{"v0.8.1-0.20261001000000-abcdefabcdef", MinInlinePolicy, false, true}, // after v0.8.0: R74 not guaranteed
		{"v0.9.0-rc1", MinInlinePolicy, true, true},
		{"v0.9.0-rc1.0.20261002000000-abcdefabcdef", MinInlinePolicy, true, true},
		{"v0.9.0", MinInlinePolicy, true, true},
		{"v1.0.0", MinInlinePolicy, true, true},
		{"", MinInlinePolicy, false, false},
		{"(devel)", MinInlinePolicy, false, false},
		{"v0.0.0-20261001000000-abcdefabcdef", MinInlinePolicy, false, false}, // no tag before it
		{"garbage", MinInlinePolicy, false, false},
	}
	for _, tc := range cases {
		ok, known := AtLeast(tc.version, tc.min)
		assert.Equal(t, tc.ok, ok, "%s >= %s", tc.version, tc.min)
		assert.Equal(t, tc.known, known, "%s known", tc.version)
	}
	ok, known := AtLeast(MinInlinePolicy, MinViolationSet)
	assert.True(t, ok && known, "MinInlinePolicy must cover MinViolationSet")
}

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
