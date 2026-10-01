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
		{"v0.7.1-rc1", MinViolationSet, false, true},                           // semver: before v0.7.1
		{"v0.8.0-rc1", MinPolicyID, false, true},                               // predate R74
		{"v0.8.0-rc4", MinPolicyID, false, true},
		{"v0.8.0-rc4.0.20261001000000-abcdefabcdef", MinPolicyID, false, true}, // after v0.8.0-rc4
		{"v0.7.2", MinPolicyID, false, true},
		{"v0.8.0", MinPolicyID, false, true},                                   // released without R74 (R81)
		{"v0.8.1", MinPolicyID, false, true},                                   // released without R74 (R81)
		{"v0.8.2-0.20261001000000-abcdefabcdef", MinPolicyID, false, true},     // after v0.8.1
		{"v0.9.0-rc1", MinPolicyID, false, true},                               // semver: before v0.9.0
		{"v0.9.0-rc1.0.20261001000000-abcdefabcdef", MinPolicyID, false, true}, // after v0.9.0-rc1
		{"v0.9.0", MinPolicyID, true, true},
		{"v0.9.1-0.20261001000000-abcdefabcdef", MinPolicyID, true, true}, // after v0.9.0
		{"v0.9.1", MinPolicyID, true, true},
		{"v0.10.0", MinPolicyID, true, true},
		{"v1.0.0", MinPolicyID, true, true},
		{"", MinPolicyID, false, false},
		{"(devel)", MinPolicyID, false, false},
		{"v0.0.0-20261001000000-abcdefabcdef", MinPolicyID, false, false}, // no tag before it
		{"garbage", MinPolicyID, false, false},
	}
	for _, tc := range cases {
		ok, known := AtLeast(tc.version, tc.min)
		assert.Equal(t, tc.ok, ok, "%s >= %s", tc.version, tc.min)
		assert.Equal(t, tc.known, known, "%s known", tc.version)
	}
	ok, known := AtLeast(MinPolicyID, MinViolationSet)
	assert.True(t, ok && known, "MinPolicyID must cover MinViolationSet")
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
