package runner

import (
	"context"
	"net/http"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPluginSource = "ghcr.io/compliance-framework/plugin-apt-versions:v0.4.0"
	testPolicySource = "ghcr.io/compliance-framework/plugin-apt-versions-policies:v0.4.0"
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
	WithSources(testPluginSource, map[string]string{bundle + "/": testPolicySource})(helper)

	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("evaluated", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
		evidenceFor("no evaluation", nil),
	}))

	props := sentProps(api)
	assert.Equal(t, testPluginSource, props["evaluated"][PropPluginSource])
	assert.Equal(t, testPolicySource, props["evaluated"][PropPolicySource])
	assert.Equal(t, testPluginSource, props["no evaluation"][PropPluginSource])
	assert.NotContains(t, props["no evaluation"], PropPolicySource, "without an evaluation the policy bundle is not known")
}

func TestStreamedReferencesRecordThePolicySource(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)
	WithSources(testPluginSource, map[string]string{bundle: testPolicySource})(helper)
	client := dialServer(t, newApiHelperGRPCServer(helper))

	evaluation := &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}
	require.NoError(t, client.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("first", evaluation),
		evidenceFor("second", evaluation), // sent as a reference to the first
	}))

	props := sentProps(api)
	assert.Equal(t, testPolicySource, props["first"][PropPolicySource])
	assert.Equal(t, testPolicySource, props["second"][PropPolicySource])
}

func TestSourcesAreRecordedWhenArtifactsCannotBeStored(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{artifactStatuses: []int{http.StatusNotFound}}
	helper := newTestHelper(t, api, bundle)
	WithSources(testPluginSource, map[string]string{bundle: testPolicySource})(helper)

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
	WithSources(testPluginSource, map[string]string{bundle: testPolicySource})(helper)

	e := evidenceFor("spoofed", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)})
	e.Props = []*proto.Property{
		{Name: PropPluginSource, Value: "ghcr.io/elsewhere/plugin:v9"},
		{Name: PropPolicySource, Value: "ghcr.io/elsewhere/policies:v9"},
		{Name: "_violation_id", Value: "kept"},
	}
	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{e}))

	require.Len(t, api.evidence, 1)
	list := api.evidence[0]["props"].([]any)
	var sources []string
	for _, p := range list {
		prop := p.(map[string]any)
		if prop["name"] == PropPluginSource || prop["name"] == PropPolicySource {
			sources = append(sources, prop["value"].(string))
		}
	}
	assert.ElementsMatch(t, []string{testPluginSource, testPolicySource}, sources, "only the agent's values are sent")
	assert.Equal(t, "kept", sentProps(api)["spoofed"]["_violation_id"])
}
