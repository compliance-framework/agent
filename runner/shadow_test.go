package runner

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/compliance-framework/agent/internal/policytree"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Path shadowing: a plugin running in a view receives a relative path that, in the view,
// resolves to an inline bundle while, from the agent's working directory, it is the vendor
// source. The agent must read what the plugin evaluated.

const shadowedPath = ".compliance-framework/policies/vendor/policies/v1/policies"

// shadowFixture returns a base (the agent's working directory, with the vendor tree at
// shadowedPath) and a view in which shadowedPath is the bundle's tree.
func shadowFixture(t *testing.T) (base, view, bundleTree string) {
	t.Helper()
	base = t.TempDir()
	vendor := filepath.Join(base, shadowedPath)
	require.NoError(t, os.MkdirAll(vendor, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(vendor, "a.rego"), []byte("package compliance_framework.a\n\ntitle := \"vendor\"\n"), 0o644))

	store := filepath.Join(t.TempDir(), "inline", "b", "0123")
	bundleTree = filepath.Join(store, "policies")
	require.NoError(t, os.MkdirAll(bundleTree, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bundleTree, "a.rego"), []byte("package compliance_framework.a\n\ntitle := \"inline\"\n"), 0o644))

	view = t.TempDir()
	link := filepath.Join(view, filepath.Dir(shadowedPath))
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
	if err := os.Symlink(store, link); err != nil {
		t.Skip("symlinks are not supported here")
	}
	t.Chdir(base)
	return base, view, bundleTree
}

func TestPolicyRootResolvesRelativePathsInTheView(t *testing.T) {
	base, view, bundleTree := shadowFixture(t)
	abs := t.TempDir()

	h := NewApiHelper(hclog.NewNullLogger(), nil, nil, "ssh", WithPolicyRoot(view), WithPolicyPaths([]string{shadowedPath, abs}))
	want, err := filepath.EvalSymlinks(bundleTree)
	require.NoError(t, err)
	assert.Equal(t, want, h.policyPaths[shadowedPath], "the agent reads the tree the plugin evaluated, not the vendor's")
	wantAbs, _ := filepath.EvalSymlinks(abs)
	assert.Equal(t, wantAbs, h.policyPaths[abs], "absolute paths are unaffected")

	inline, err := policytree.TarDirectory(h.policyPaths[shadowedPath])
	require.NoError(t, err)
	vendor, err := policytree.TarDirectory(filepath.Join(base, shadowedPath))
	require.NoError(t, err)
	assert.NotEqual(t, vendor, inline)

	// Without a root (no view) the agent's working directory is used, as before.
	plain := NewApiHelper(hclog.NewNullLogger(), nil, nil, "ssh", WithPolicyPaths([]string{shadowedPath}))
	assert.Equal(t, shadowedPath, plain.policyPaths[shadowedPath])
}

// TestPolicySourceFromThePolicyPathLabel: a plugin built on an agent library without policy
// evaluations still labels its evidence with _policy_path; the agent records the source of
// that path, which for a shadowed path is the inline bundle.
func TestPolicySourceFromThePolicyPathLabel(t *testing.T) {
	_, view, _ := shadowFixture(t)
	api := &fakeAPI{}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	client := sdk.NewClient(server.Client(), &sdk.Config{BaseURL: server.URL})
	inline := Source{Reference: "inline:b", Digest: "tree:sha256:abcd", BundleArtifact: true}
	h := NewApiHelper(hclog.NewNullLogger(), client, nil, "ssh",
		WithPolicyRoot(view), WithPolicyPaths([]string{shadowedPath}),
		WithSources(testPlugin, map[string]Source{shadowedPath: inline}))

	labelled := &proto.Evidence{UUID: "11111111-1111-1111-1111-111111111111", Title: "old plugin", Labels: map[string]string{LabelPolicyPath: shadowedPath}}
	unknown := &proto.Evidence{UUID: "11111111-1111-1111-1111-111111111112", Title: "other path", Labels: map[string]string{LabelPolicyPath: "elsewhere"}}
	require.NoError(t, h.CreateEvidence(context.Background(), []*proto.Evidence{labelled, unknown}))

	props := sentProps(api)
	assert.Equal(t, "inline:b", props["old plugin"][PropPolicySource])
	assert.Equal(t, "tree:sha256:abcd", props["old plugin"][PropPolicyDigest], "no artifact was stored: the tree digest")
	assert.NotContains(t, props["other path"], PropPolicySource, "a path the plugin was not given records nothing")
}
