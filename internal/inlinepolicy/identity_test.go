package inlinepolicy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentities(t *testing.T) {
	ids := Identities(map[string][]byte{
		"a.rego":        []byte("package compliance_framework.a\n\npolicy_id := \"a-id\"\n\ntitle := \"a\"\n"),
		"a_extra.rego":  []byte("package compliance_framework.a\n\ntitle2 := \"x\"\n"),
		"a_test.rego":   []byte("package compliance_framework.a\n\npolicy_id := \"ignored\"\n"),
		"b/b.rego":      []byte("package compliance_framework.b\n\ntitle := \"b\"\n"),
		"twice.rego":    []byte("package compliance_framework.twice\n\npolicy_id := \"one\"\n"),
		"twice2.rego":   []byte("package compliance_framework.twice\n\npolicy_id := \"two\"\n"),
		"cond.rego":     []byte("package compliance_framework.cond\n\npolicy_id := \"c\" if input.x\n"),
		"computed.rego": []byte("package compliance_framework.computed\n\npolicy_id := concat(\"-\", [\"a\", \"b\"])\n"),
		"lib.rego":      []byte("package ccf_libs.helpers\n\npolicy_id := \"lib\"\n"),
		"broken.rego":   []byte("package compliance_framework.broken\n\ntitle := \n"),
		"data.json":     []byte("{}"),
	})
	assert.Equal(t, []ModuleIdentity{
		{Path: "a.rego", Package: "compliance_framework.a", PolicyID: "a-id"},
		{Path: "a_extra.rego", Package: "compliance_framework.a", PolicyID: "a-id"}, // the package's policy_id
		{Path: "b/b.rego", Package: "compliance_framework.b"},
		{Path: "computed.rego", Package: "compliance_framework.computed"}, // only literals count
		{Path: "cond.rego", Package: "compliance_framework.cond"},
		{Path: "twice.rego", Package: "compliance_framework.twice"}, // declared twice: none
		{Path: "twice2.rego", Package: "compliance_framework.twice"},
	}, ids)
}

func TestAuthoredSites(t *testing.T) {
	files := map[string][]byte{
		"set.rego":      []byte("package compliance_framework.set\n\nimport rego.v1\n\npolicy_id := \"s\"\n\nviolation contains {\"id\": \"x\"} if input.bad\n"),
		"object.rego":   []byte("package compliance_framework.object\n\nimport rego.v1\n\nviolation[{\"id\": \"x\"}] if input.bad\n"),
		"vendor.rego":   []byte("package compliance_framework.vendor\n\nimport rego.v1\n\nviolation contains {\"id\": \"x\"} if input.bad\n"),
		"set_test.rego": []byte("package compliance_framework.set\n\nimport rego.v1\n\nviolation contains 1 if true\n"),
	}
	set, ids := authoredSites(files, map[string]bool{"set.rego": true, "object.rego": true, "set_test.rego": true})
	assert.Equal(t, []Site{{Path: "set.rego", Row: 7, Col: 1}}, set, "only authored set-form violations; the object form works with every plugin")
	assert.Equal(t, []Site{{Path: "set.rego", Row: 5, Col: 1}}, ids)
}

// TestOverrideStreams_R75: an override continues the vendor module's stream only with the
// vendor's package and policy_id, or, when the vendor has none, the vendor's legacy policy
// file as its policy_id.
func TestOverrideStreams_R75(t *testing.T) {
	const vendorID = "package compliance_framework.ided\n\nimport rego.v1\n\npolicy_id := \"vendor-id\"\n\ntitle := \"x\"\n"
	dir, resolve := vendorTree(t, map[string]string{"banner.rego": vendorBanner, "max_auth.rego": vendorMaxAuth, "ided.rego": vendorID})
	continuing := "package compliance_framework.banner\n\nimport rego.v1\n\npolicy_id := \"" + ContinuityPolicyID(dir, "banner.rego") + "\"\n\ntitle := \"Banner\"\n"
	cases := []struct {
		name    string
		modules map[string]string
		want    map[string]string // path -> code
	}{
		{"continues the legacy stream", map[string]string{"banner.rego": continuing}, map[string]string{}},
		{"keeps the vendor policy_id", map[string]string{"ided.rego": vendorID + "\n# changed\n"}, map[string]string{}},
		// R82: the agent appends the continuity policy_id to an override without one.
		{"no policy_id", map[string]string{"banner.rego": vendorBanner + "\n# changed\n"}, map[string]string{}},
		{"no policy_id in a package of two modules", map[string]string{"banner.rego": vendorBanner + "\n# changed\n", "banner_more.rego": "package compliance_framework.banner\n\nmore := true\n"}, map[string]string{"banner.rego": CodePolicyStreamForked}},
		{"changed policy_id", map[string]string{"ided.rego": "package compliance_framework.ided\n\npolicy_id := \"other\"\n\ntitle := \"x\"\n"}, map[string]string{"ided.rego": CodePolicyStreamForked}},
		// R82: the agent appends the vendor package's policy_id.
		{"removed policy_id", map[string]string{"ided.rego": "package compliance_framework.ided\n\ntitle := \"x\"\n"}, map[string]string{}},
		{"changed package", map[string]string{"max_auth.rego": "package compliance_framework.max_auth_v2\n\ntitle := \"x\"\n"}, map[string]string{"max_auth.rego": agentconfig.PolicyCodePolicyPackageChanged}},
		{"new module", map[string]string{"new.rego": "package compliance_framework.new\n\ntitle := \"x\"\n"}, map[string]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Materialize(context.Background(), testLayout(t.TempDir()), "b", &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Modules: tc.modules}, resolve)
			require.NoError(t, err)
			got := map[string]string{}
			for _, e := range OverrideStreams(m) {
				require.Equal(t, agentconfig.SeverityWarning, e.Severity)
				require.Equal(t, "b", e.Bundle)
				got[e.Path] = e.Code
			}
			assert.Equal(t, tc.want, got)
		})
	}
	m, err := Materialize(context.Background(), testLayout(t.TempDir()), "b", &agentconfig.PolicyBundle{Modules: map[string]string{"banner.rego": vendorBanner}}, resolve)
	require.NoError(t, err)
	assert.Empty(t, OverrideStreams(m), "a bundle without extends overrides nothing")
}

// TestOverrideStreams_NonCleanLocalSource_R77: for a local source configured with a
// non-clean path, the continuity policy_id is the literal "<plugin path>/<file>", and the
// override continues the stream; the cleaned join does not (plugins that label _policy_path
// seed with the literal path).
func TestOverrideStreams_NonCleanLocalSource_R77(t *testing.T) {
	for _, pluginPath := range []string{"./policies", "./policies/", "policies/"} {
		t.Run(pluginPath, func(t *testing.T) {
			t.Chdir(t.TempDir())
			require.NoError(t, os.MkdirAll("policies", 0o755))
			require.NoError(t, os.WriteFile(filepath.Join("policies", "banner.rego"), []byte(vendorBanner), 0o644))
			resolve := func(_ context.Context, source string) (string, error) { return pluginPath, nil }
			want := ContinuityPolicyID(pluginPath, "banner.rego")
			assert.Equal(t, pluginPath+"/banner.rego", want, "the literal concatenation")

			override := func(id string) []agentconfig.PolicyError {
				t.Helper()
				src := "package compliance_framework.banner\n\npolicy_id := \"" + id + "\"\n\ntitle := \"Banner\"\n"
				m, err := Materialize(context.Background(), testLayout(t.TempDir()), "b", &agentconfig.PolicyBundle{Extends: strptr("local"), Modules: map[string]string{"banner.rego": src}}, resolve)
				require.NoError(t, err)
				return OverrideStreams(m)
			}
			assert.Empty(t, override(want), "the literal continuity policy_id continues the stream")

			forked := override("policies/banner.rego")
			require.Len(t, forked, 1, "the cleaned path seeds a different _policy_path")
			assert.Equal(t, CodePolicyStreamForked, forked[0].Code)
			assert.Contains(t, forked[0].Message, fmt.Sprintf("policy_id := %q", want), "the warning names the literal continuity policy_id")
		})
	}
}
