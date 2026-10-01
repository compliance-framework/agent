package policyview

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// warnings records View.Warn calls.
type warnings struct {
	mu   sync.Mutex
	logs []string
}

func (w *warnings) warn(msg string, args ...interface{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logs = append(w.logs, fmt.Sprint(append([]interface{}{msg}, args...)...))
}

func (w *warnings) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.logs)
}

// shadowedView is a view of base with the bundle tree target linked at vendor/.
func shadowedView(t *testing.T, base string, w *warnings) View {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(base, "vendor", "policies"), 0o755))
	target := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(target, "policies"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(target, "policies", "bundle.rego"), []byte("bundle"), 0o644))
	links := map[string]string{"vendor": target}
	v := View{Dir: DirFor(filepath.Join(t.TempDir(), "views"), "custodian", base, links), Base: base, Links: links}
	if w != nil {
		v.Warn = w.warn
	}
	if err := v.Ensure(); err != nil {
		if os.IsPermission(err) {
			t.Skip(err)
		}
		require.NoError(t, err)
	}
	return v
}

// TestEnsure_PluginOwnedEntriesAreKept (rule 1): a plugin that creates a directory relative to
// its working directory (cloud-custodian's debug-standardized-payloads) creates it in its view;
// when the agent's working directory later gets an entry of the same name, the plugin keeps
// its own, Ensure warns once and succeeds.
func TestEnsure_PluginOwnedEntriesAreKept(t *testing.T) {
	base := t.TempDir()
	w := &warnings{}
	v := shadowedView(t, base, w)

	// The plugin creates a directory and a file in its working directory.
	owned := filepath.Join(v.Dir, "debug-standardized-payloads")
	require.NoError(t, os.MkdirAll(owned, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(owned, "payload.json"), []byte("plugin"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir, "out.log"), []byte("plugin log"), 0o644))
	require.NoError(t, v.Ensure(), "entries only the view has are left alone")
	assert.Zero(t, w.count())

	// Later the agent's working directory gets the same names.
	require.NoError(t, os.MkdirAll(filepath.Join(base, "debug-standardized-payloads"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(base, "debug-standardized-payloads", "agent.json"), []byte("agent"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(base, "out.log"), []byte("agent log"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(base, "fresh.txt"), []byte("fresh"), 0o644))

	for range 3 {
		require.NoError(t, v.Ensure(), "a plugin-owned entry never fails Ensure")
	}
	assert.Equal(t, 2, w.count(), "one warning per plugin-owned name, not one per Ensure: %v", w.logs)
	assert.Contains(t, strings.Join(w.logs, "\n"), "debug-standardized-payloads")

	info, err := os.Lstat(owned)
	require.NoError(t, err)
	assert.True(t, info.IsDir() && info.Mode()&os.ModeSymlink == 0, "the plugin's directory is not replaced by a mirror link")
	raw, err := os.ReadFile(filepath.Join(owned, "payload.json"))
	require.NoError(t, err)
	assert.Equal(t, "plugin", string(raw))
	_, err = os.Stat(filepath.Join(owned, "agent.json"))
	assert.True(t, os.IsNotExist(err), "the agent's entry is hidden from the plugin")
	raw, err = os.ReadFile(filepath.Join(v.Dir, "out.log"))
	require.NoError(t, err)
	assert.Equal(t, "plugin log", string(raw))
	raw, err = os.ReadFile(filepath.Join(base, "out.log"))
	require.NoError(t, err)
	assert.Equal(t, "agent log", string(raw), "the agent's entry is untouched")

	// Other entries are still mirrored, and the shadowed path is still the bundle.
	raw, err = os.ReadFile(filepath.Join(v.Dir, "fresh.txt"))
	require.NoError(t, err)
	assert.Equal(t, "fresh", string(raw))
	raw, err = os.ReadFile(filepath.Join(v.Dir, "vendor", "policies", "bundle.rego"))
	require.NoError(t, err)
	assert.Equal(t, "bundle", string(raw))

	// A view without a Warn hook behaves the same, silently.
	silent := v
	silent.Warn = nil
	require.NoError(t, silent.Ensure())
}

// TestEnsure_PluginOwnedEntryInANestedViewDirectory: the same holds below the view root.
func TestEnsure_PluginOwnedEntryInANestedViewDirectory(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(base, "a", "vendor", "policies"), 0o755))
	target := t.TempDir()
	links := map[string]string{"a/vendor": target}
	w := &warnings{}
	v := View{Dir: DirFor(filepath.Join(t.TempDir(), "views"), "p", base, links), Base: base, Links: links, Warn: w.warn}
	require.NoError(t, v.Ensure())
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir, "a", "cache"), []byte("plugin"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(base, "a", "cache"), []byte("agent"), 0o644))
	require.NoError(t, v.Ensure())
	require.NoError(t, v.Ensure())
	assert.Equal(t, 1, w.count())
	raw, err := os.ReadFile(filepath.Join(v.Dir, "a", "cache"))
	require.NoError(t, err)
	assert.Equal(t, "plugin", string(raw))
}

// TestEnsure_ConflictAtTheShadowLink: the shadow link is the agent's; a real entry at its
// path (the plugin removed the link and created its own) is a clear error, and Ensure leaves
// the entry alone.
func TestEnsure_ConflictAtTheShadowLink(t *testing.T) {
	base := t.TempDir()
	v := shadowedView(t, base, &warnings{})
	link := filepath.Join(v.Dir, "vendor")
	require.NoError(t, os.Remove(link))
	require.NoError(t, os.MkdirAll(filepath.Join(link, "policies"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(link, "policies", "mine.rego"), []byte("plugin"), 0o644))

	err := v.Ensure()
	var conflict *LinkConflictError
	require.ErrorAs(t, err, &conflict)
	assert.Equal(t, LinkConflictError{View: v.Dir, Link: "vendor"}, *conflict)
	assert.Contains(t, err.Error(), "shadowed policy path")
	raw, rerr := os.ReadFile(filepath.Join(link, "policies", "mine.rego"))
	require.NoError(t, rerr, "the conflicting entry is not removed")
	assert.Equal(t, "plugin", string(raw))

	// Removing the view (GC, or by hand) rebuilds it cleanly.
	require.NoError(t, os.RemoveAll(v.Dir))
	require.NoError(t, v.Ensure())
	raw, rerr = os.ReadFile(filepath.Join(link, "policies", "bundle.rego"))
	require.NoError(t, rerr)
	assert.Equal(t, "bundle", string(raw))
}

// TestEnsure_ReplacesAStaleMirrorLink: a mirror link to something else is the agent's and is
// replaced atomically, leaving no temporary link behind.
func TestEnsure_ReplacesAStaleMirrorLink(t *testing.T) {
	base := t.TempDir()
	v := shadowedView(t, base, nil)
	require.NoError(t, os.WriteFile(filepath.Join(base, "cfg"), []byte("cfg"), 0o644))
	require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(v.Dir, "cfg")))
	require.NoError(t, v.Ensure())
	cur, err := os.Readlink(filepath.Join(v.Dir, "cfg"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "cfg"), cur)
	entries, err := os.ReadDir(v.Dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".tmp-link", "no temporary link left behind")
	}
}

// TestGC_RemovesPluginOwnedEntriesWithoutFollowingLinks: GC removes a whole view, plugin-owned
// entries included, but never what a link (a mirror link, the shadow link, or a link the
// plugin made itself) points to; and a view rebuilt in the same place warns again.
func TestGC_RemovesPluginOwnedEntriesWithoutFollowingLinks(t *testing.T) {
	base := t.TempDir()
	w := &warnings{}
	v := shadowedView(t, base, w)
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("keep"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(base, "agent.txt"), []byte("agent"), 0o644))
	owned := filepath.Join(v.Dir, "debug-standardized-payloads")
	require.NoError(t, os.MkdirAll(owned, 0o755))
	require.NoError(t, os.Symlink(outside, filepath.Join(owned, "elsewhere")))
	require.NoError(t, os.MkdirAll(filepath.Join(base, "debug-standardized-payloads"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(base, "debug-standardized-payloads", "agent.json"), []byte("agent"), 0o644))
	require.NoError(t, v.Ensure())
	require.Equal(t, 1, w.count())

	// A symlinked plugin directory under the root is not followed either.
	root := filepath.Dir(filepath.Dir(v.Dir))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))

	require.NoError(t, GC(root, map[string]struct{}{}))
	_, err := os.Lstat(v.Dir)
	assert.True(t, os.IsNotExist(err), "the view, plugin-owned entries included, is removed")
	for _, p := range []string{
		filepath.Join(outside, "keep.txt"),
		filepath.Join(base, "agent.txt"),
		filepath.Join(base, "debug-standardized-payloads", "agent.json"),
		filepath.Join(base, "vendor", "policies"),
		filepath.Join(v.Links["vendor"], "policies", "bundle.rego"),
	} {
		_, err := os.Stat(p)
		assert.NoError(t, err, "GC must not follow links: %s", p)
	}
	_, err = os.Lstat(filepath.Join(root, "linked"))
	assert.NoError(t, err, "a symlinked plugin directory is skipped")

	// Rebuilt in the same place, the view warns again for a new plugin-owned entry.
	require.NoError(t, v.Ensure())
	require.NoError(t, os.Remove(filepath.Join(v.Dir, "debug-standardized-payloads")))
	require.NoError(t, os.MkdirAll(owned, 0o755))
	require.NoError(t, v.Ensure())
	assert.Equal(t, 2, w.count())
}
