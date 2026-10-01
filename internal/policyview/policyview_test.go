package policyview

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const oci = ".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0/policies"

func TestShadowable(t *testing.T) {
	for p, ok := range map[string]bool{
		oci:                        true,
		"./" + oci:                 true,
		"vendor/policies":          true,
		"policies":                 false, // no parent to link
		"./policies":               false,
		"/abs/x/policies":          false,
		"../x/policies":            false,
		".compliance-framework/x":  false, // not a policies/ tree
		"":                         false,
		"a/../b/policies":          true,
		"a/policies/../x/policies": true,
	} {
		assert.Equal(t, ok, Shadowable(p) == nil, p)
	}
}

func TestPlan(t *testing.T) {
	links, err := Plan([]string{oci}, []string{
		".compliance-framework/policies/inline/custom/policies",                                         // R82 inline path
		".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.1.0/policies", // another tag: a mirrored sibling
		"/etc/ccf/policies", // absolute: unaffected
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{oci: ".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0"}, links)

	for name, tc := range map[string]struct{ shadowed, others []string }{
		"same path twice":            {[]string{oci, "./" + oci}, nil},
		"nested links":               {[]string{"a/policies", "a/policies/b/policies"}, nil},
		"other inside a shadow":      {[]string{oci}, []string{oci + "/sub"}},
		"other is the shadowed path": {[]string{oci}, []string{oci}},
		"other is a view directory":  {[]string{oci}, []string{".compliance-framework/policies"}},
		"other directly in a view dir (leaf would be a mirrored symlink)": {[]string{"vendor/policies"}, []string{"local-policies"}},
		"not shadowable": {[]string{"/abs/policies"}, nil},
	} {
		_, err := Plan(tc.shadowed, tc.others)
		assert.Error(t, err, name)
	}
}

func TestEnsure(t *testing.T) {
	base := t.TempDir()
	mk := func(p, content string) {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(base, p)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(base, p), []byte(content), 0o644))
	}
	mk(oci+"/vendor.rego", "vendor")
	mk(".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.1.0/policies/old.rego", "old")
	mk(".compliance-framework/policies/inline/custom/policies/x.rego", "inline")
	mk("config.yml", "cfg")
	target := filepath.Join(t.TempDir(), "b", "0123")
	require.NoError(t, os.MkdirAll(filepath.Join(target, "policies"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(target, "policies", "bundle.rego"), []byte("bundle"), 0o644))

	links := map[string]string{LinkOf(oci): target}
	v := View{Dir: DirFor(filepath.Join(t.TempDir(), "views"), "ssh", base, links), Base: base, Links: links}
	if err := v.Ensure(); err != nil {
		if os.IsPermission(err) {
			t.Skip(err)
		}
		require.NoError(t, err)
	}
	read := func(p string) string {
		raw, err := os.ReadFile(filepath.Join(v.Dir, p))
		require.NoError(t, err, p)
		return string(raw)
	}
	assert.Equal(t, "bundle", read(oci+"/bundle.rego"), "the shadowed path is the bundle")
	_, err := os.Stat(filepath.Join(v.Dir, oci, "vendor.rego"))
	assert.True(t, os.IsNotExist(err), "the vendor tree is hidden")
	assert.Equal(t, "old", read(".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.1.0/policies/old.rego"))
	assert.Equal(t, "inline", read(".compliance-framework/policies/inline/custom/policies/x.rego"))
	assert.Equal(t, "cfg", read("config.yml"), "other entries of the working directory are mirrored")
	info, err := os.Lstat(filepath.Join(v.Dir, oci))
	require.NoError(t, err)
	assert.True(t, info.IsDir(), "the leaf is a real directory (OPA does not load a symlinked root)")

	// Idempotent, and picks up entries created since.
	mk("later.txt", "later")
	require.NoError(t, v.Ensure())
	assert.Equal(t, "later", read("later.txt"))

	// Deterministic directory, and a different target is a different view.
	assert.Equal(t, v.Dir, DirFor(filepath.Dir(filepath.Dir(v.Dir)), "ssh", base, links))
	assert.NotEqual(t, v.Dir, DirFor(filepath.Dir(filepath.Dir(v.Dir)), "ssh", base, map[string]string{LinkOf(oci): target + "x"}))

	// GC removes unkept views without following their links.
	other := View{Dir: DirFor(filepath.Dir(filepath.Dir(v.Dir)), "ssh", base, map[string]string{LinkOf(oci): target}), Base: base, Links: links}
	require.Equal(t, v.Dir, other.Dir)
	require.NoError(t, GC(filepath.Dir(filepath.Dir(v.Dir)), map[string]struct{}{}))
	_, err = os.Lstat(v.Dir)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(target, "policies", "bundle.rego"))
	assert.NoError(t, err, "GC must not follow the view's links")
	_, err = os.Stat(filepath.Join(base, oci, "vendor.rego"))
	assert.NoError(t, err)
}

func TestEnsureNeverMirrorsTheViewIntoItself(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(base, "vendor", "policies"), 0o755))
	target := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(target, "policies"), 0o755))
	links := map[string]string{"vendor": target}
	// The views live under the base's state directory, like the agent's.
	v := View{Dir: DirFor(filepath.Join(base, "state", "views"), "ssh", base, links), Base: base, Links: links}
	require.NoError(t, v.Ensure())
	_, err := os.Lstat(filepath.Join(v.Dir, "state"))
	assert.True(t, os.IsNotExist(err), "the directory holding the view is not mirrored")
}
