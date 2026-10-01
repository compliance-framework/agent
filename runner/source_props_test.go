package runner

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPluginSource = "ghcr.io/compliance-framework/plugin-apt-versions:v0.4.0"
	testPolicySource = "ghcr.io/compliance-framework/plugin-apt-versions-policies:v0.4.0"
	testPluginDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testPolicyDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

var (
	testPlugin = Source{Reference: testPluginSource, Digest: testPluginDigest}
	testPolicy = Source{Reference: testPolicySource, Digest: testPolicyDigest}
)

// sentProps returns each sent evidence's props by title, as name -> value.
func sentProps(api *fakeAPI) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, e := range api.evidence {
		props := map[string]string{}
		list, _ := e["props"].([]any)
		for _, p := range list {
			prop := p.(map[string]any)
			props[prop["name"].(string)] = prop["value"].(string)
		}
		out[e["title"].(string)] = props
	}
	return out
}

func TestEvidenceRecordsPluginAndPolicySources(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)
	WithSources(testPlugin, map[string]Source{bundle + "/": testPolicy})(helper)

	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("evaluated", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
		evidenceFor("no evaluation", nil),
	}))

	props := sentProps(api)
	assert.Equal(t, testPluginSource, props["evaluated"][PropPluginSource])
	assert.Equal(t, testPluginDigest, props["evaluated"][PropPluginDigest])
	assert.Equal(t, testPolicySource, props["evaluated"][PropPolicySource])
	assert.Equal(t, testPolicyDigest, props["evaluated"][PropPolicyDigest])
	assert.Equal(t, testPluginSource, props["no evaluation"][PropPluginSource])
	assert.Equal(t, testPluginDigest, props["no evaluation"][PropPluginDigest])
	assert.NotContains(t, props["no evaluation"], PropPolicySource, "without an evaluation the policy bundle is not known")
	assert.NotContains(t, props["no evaluation"], PropPolicyDigest)
}

func TestStreamedReferencesRecordThePolicySource(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)
	WithSources(testPlugin, map[string]Source{bundle: testPolicy})(helper)
	client := dialServer(t, newApiHelperGRPCServer(helper))

	evaluation := &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}
	require.NoError(t, client.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("first", evaluation),
		evidenceFor("second", evaluation), // sent as a reference to the first
	}))

	props := sentProps(api)
	assert.Equal(t, testPolicySource, props["first"][PropPolicySource])
	assert.Equal(t, testPolicySource, props["second"][PropPolicySource])
	assert.Equal(t, testPolicyDigest, props["second"][PropPolicyDigest])
}

func TestSourcesAreRecordedWhenArtifactsCannotBeStored(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{artifactStatuses: []int{http.StatusNotFound}}
	helper := newTestHelper(t, api, bundle)
	WithSources(testPlugin, map[string]Source{bundle: testPolicy})(helper)

	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("old api", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
	}))
	props := sentProps(api)
	assert.Equal(t, testPluginSource, props["old api"][PropPluginSource])
	assert.Equal(t, testPolicySource, props["old api"][PropPolicySource])
	assert.Nil(t, artifactsOf(api)["old api"])
}

func TestNoSourcePropsWithoutSources(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)

	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("one", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
	}))
	assert.NotContains(t, sentProps(api)["one"], PropPluginSource)
	assert.NotContains(t, sentProps(api)["one"], PropPolicySource)
}

func TestPluginCannotSetTheSourceProps(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)
	WithSources(testPlugin, map[string]Source{bundle: testPolicy})(helper)

	e := evidenceFor("spoofed", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)})
	e.Props = []*proto.Property{
		{Name: PropPluginSource, Value: "ghcr.io/elsewhere/plugin:v9"},
		{Name: PropPluginDigest, Value: "sha256:spoofed"},
		{Name: PropPolicySource, Value: "ghcr.io/elsewhere/policies:v9"},
		{Name: PropPolicyDigest, Value: "sha256:spoofed"},
		{Name: "_violation_id", Value: "kept"},
	}
	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{e}))

	require.Len(t, api.evidence, 1)
	list := api.evidence[0]["props"].([]any)
	var sources []string
	for _, p := range list {
		prop := p.(map[string]any)
		if isSourceProp(prop["name"].(string)) {
			sources = append(sources, prop["value"].(string))
		}
	}
	assert.ElementsMatch(t, []string{testPluginSource, testPluginDigest, testPolicySource, testPolicyDigest}, sources, "only the agent's values are sent")
	assert.Equal(t, "kept", sentProps(api)["spoofed"]["_violation_id"])
}

func TestSourceWithoutDigestRecordsOnlyTheReference(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)
	// As for files extracted before digests were recorded.
	WithSources(Source{Reference: testPluginSource}, map[string]Source{bundle: {Reference: testPolicySource}})(helper)

	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("old cache", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
	}))
	props := sentProps(api)["old cache"]
	assert.Equal(t, testPluginSource, props[PropPluginSource])
	assert.Equal(t, testPolicySource, props[PropPolicySource])
	assert.NotContains(t, props, PropPluginDigest)
	assert.NotContains(t, props, PropPolicyDigest)
}

// TestInlineBundleRecordsItsEntryAndArtifactDigest: an inline bundle is keyed by the stable
// path the plugin receives (R67), a symlink to the bundle's tree, and records its entry and
// the artifact digest of the bundle the evaluation stored (design §13.4).
func TestInlineBundleRecordsItsEntryAndArtifactDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	tree := filepath.Join(base, "0123abcd")
	require.NoError(t, os.MkdirAll(filepath.Join(tree, "bundle"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "bundle", "p.rego"), []byte("package compliance_framework.p\n\ntitle := \"p\"\n"), 0o644))
	require.NoError(t, os.Symlink("0123abcd", filepath.Join(base, "current")))
	stable := filepath.Join(base, "current", "bundle")

	inline := Source{Reference: "inline:ssh", Digest: "tree:sha256:3333", BundleArtifact: true}
	api := &fakeAPI{}
	helper := newTestHelper(t, api, stable)
	WithSources(testPlugin, map[string]Source{stable: inline})(helper)

	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("inline", &proto.PolicyEvaluation{PolicyPath: stable, Input: []byte(`{}`)}),
	}))
	props := sentProps(api)["inline"]
	refs := artifactsOf(api)["inline"].(map[string]any)
	assert.Equal(t, "inline:ssh", props[PropPolicySource])
	assert.Equal(t, refs["bundle-digest"], props[PropPolicyDigest], "the bundle's artifact digest")
}

func TestInlineBundleFallsBackToItsTreeDigest(t *testing.T) {
	bundle := writeBundle(t, "a")
	inline := Source{Reference: "inline:ssh", Digest: "tree:sha256:3333", BundleArtifact: true}
	api := &fakeAPI{artifactStatuses: []int{http.StatusRequestEntityTooLarge}}
	helper := newTestHelper(t, api, bundle)
	WithSources(testPlugin, map[string]Source{bundle: inline})(helper)

	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("too large", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
	}))
	props := sentProps(api)["too large"]
	assert.Nil(t, artifactsOf(api)["too large"])
	assert.Equal(t, "inline:ssh", props[PropPolicySource])
	assert.Equal(t, "tree:sha256:3333", props[PropPolicyDigest])
}
