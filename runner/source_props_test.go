package runner

import (
	"context"
	"net/http"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk/types"
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

// TestPolicyPathLabelRecordsThePolicySource: evidence without a policy evaluation (plugins
// built on an older agent library) records the source of the policy path it is labelled with,
// when that path is one the plugin was given.
func TestPolicyPathLabelRecordsThePolicySource(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)
	WithSources(testPlugin, map[string]Source{bundle: testPolicy})(helper)

	labelled := evidenceFor("labelled", nil)
	labelled.Labels = map[string]string{LabelPolicyPath: bundle + "/"}
	unknown := evidenceFor("unknown path", nil)
	unknown.Labels = map[string]string{LabelPolicyPath: "/elsewhere/policies"}
	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{labelled, unknown}))

	props := sentProps(api)
	assert.Equal(t, testPolicySource, props["labelled"][PropPolicySource])
	assert.Equal(t, testPolicyDigest, props["labelled"][PropPolicyDigest])
	assert.NotContains(t, props["unknown path"], PropPolicySource, "a path the plugin was not given records nothing")
}

// TestPluginCannotSetTheConfigRevision: the agent's revision prop replaces a plugin's, and a
// plugin's is dropped when the agent sets none (it runs the file only).
func TestPluginCannotSetTheConfigRevision(t *testing.T) {
	spoofed := func() *proto.Evidence {
		e := evidenceFor("spoofed", nil)
		e.Props = []*proto.Property{
			{Ns: new(PropNamespace), Name: PropConfigRevision, Value: "99"},
			{Ns: new("https://example.test/ns"), Name: PropConfigRevision, Value: "kept"},
		}
		return e
	}
	revisions := func(api *fakeAPI) []string {
		var out []string
		for _, p := range api.evidence[0]["props"].([]any) {
			prop := p.(map[string]any)
			if prop["name"] == PropConfigRevision {
				out = append(out, prop["ns"].(string)+"="+prop["value"].(string))
			}
		}
		return out
	}

	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)
	WithEvidenceProps(types.Property{Ns: PropNamespace, Name: PropConfigRevision, Value: "7"})(helper)
	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{spoofed()}))
	assert.ElementsMatch(t, []string{"https://example.test/ns=kept", PropNamespace + "=7"}, revisions(api), "the agent's revision wins")

	api = &fakeAPI{}
	helper = newTestHelper(t, api, bundle)
	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{spoofed()}))
	assert.Equal(t, []string{"https://example.test/ns=kept"}, revisions(api), "without an applied revision a plugin's is dropped")
}
