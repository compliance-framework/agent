package inlinepolicy

import (
	"context"
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
		// Only `policy_id := "<literal>"` rules define it (policyeval.StaticPolicyIDs): a
		// function or a set is a contract error, not a second definition.
		"fn.rego":     []byte("package compliance_framework.fn\n\npolicy_id := \"fn-id\"\n\npolicy_id(x) := x\n"),
		"set.rego":    []byte("package compliance_framework.set\n\npolicy_id := \"set-id\"\n\npolicy_id contains \"y\"\n"),
		"broken.rego": []byte("package compliance_framework.broken\n\ntitle := \n"),
		"data.json":   []byte("{}"),
	})
	assert.Equal(t, []ModuleIdentity{
		{Path: "a.rego", Package: "compliance_framework.a", PolicyID: "a-id"},
		{Path: "a_extra.rego", Package: "compliance_framework.a", PolicyID: "a-id"}, // the package's policy_id
		{Path: "b/b.rego", Package: "compliance_framework.b"},
		{Path: "computed.rego", Package: "compliance_framework.computed"}, // only literals count
		{Path: "cond.rego", Package: "compliance_framework.cond"},
		{Path: "fn.rego", Package: "compliance_framework.fn", PolicyID: "fn-id"},
		{Path: "set.rego", Package: "compliance_framework.set", PolicyID: "set-id"},
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

// TestOverrideStreams_R75: an override continues the vendor module's stream at the vendor's
// path only with the vendor's package and the vendor's policy_id (or one that names the
// vendor's policy file). Served at the bundle's own path (not shadowed), the modules that do
// are UnshadowedForks.
func TestOverrideStreams_R75(t *testing.T) {
	const vendorID = "package compliance_framework.ided\n\nimport rego.v1\n\npolicy_id := \"vendor-id\"\n\ntitle := \"x\"\n"
	dir, resolve := vendorTree(t, map[string]string{"banner.rego": vendorBanner, "max_auth.rego": vendorMaxAuth, "ided.rego": vendorID})
	continuing := "package compliance_framework.banner\n\nimport rego.v1\n\npolicy_id := \"" + dir + "/banner.rego\"\n\ntitle := \"Banner\"\n"
	cases := []struct {
		name    string
		modules map[string]string
		want    map[string]string // path -> code
		forks   []string
	}{
		{"continues the legacy stream", map[string]string{"banner.rego": continuing}, map[string]string{}, []string{"max_auth.rego"}},
		{"keeps the vendor policy_id", map[string]string{"ided.rego": vendorID + "\n# changed\n"}, map[string]string{}, []string{"banner.rego", "max_auth.rego"}},
		{"no policy_id", map[string]string{"banner.rego": vendorBanner + "\n# changed\n"}, map[string]string{}, []string{"banner.rego", "max_auth.rego"}},
		{"changed policy_id", map[string]string{"ided.rego": "package compliance_framework.ided\n\npolicy_id := \"other\"\n\ntitle := \"x\"\n"}, map[string]string{"ided.rego": CodePolicyStreamForked}, []string{"banner.rego", "max_auth.rego"}},
		{"removed policy_id", map[string]string{"ided.rego": "package compliance_framework.ided\n\ntitle := \"x\"\n"}, map[string]string{"ided.rego": CodePolicyStreamForked}, []string{"banner.rego", "max_auth.rego"}},
		{"changed package", map[string]string{"max_auth.rego": "package compliance_framework.max_auth_v2\n\ntitle := \"x\"\n"}, map[string]string{"max_auth.rego": agentconfig.PolicyCodePolicyPackageChanged}, []string{"banner.rego"}},
		{"new module", map[string]string{"new.rego": "package compliance_framework.new\n\ntitle := \"x\"\n"}, map[string]string{}, []string{"banner.rego", "max_auth.rego"}},
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
			assert.Equal(t, tc.forks, UnshadowedForks(m))
		})
	}
	m, err := Materialize(context.Background(), testLayout(t.TempDir()), "b", &agentconfig.PolicyBundle{Modules: map[string]string{"banner.rego": vendorBanner}}, resolve)
	require.NoError(t, err)
	assert.Empty(t, OverrideStreams(m), "a bundle without extends overrides nothing")
	assert.Empty(t, UnshadowedForks(m))
}

// TestUnshadowedForks_NonCleanLocalSource: for a local source configured with a non-clean
// path, an authored policy_id that is the literal "<plugin path>/<file>" keeps the stream at
// the bundle's own path; the cleaned join does not (plugins label _policy_path with the
// literal path).
func TestUnshadowedForks_NonCleanLocalSource(t *testing.T) {
	for _, pluginPath := range []string{"./policies", "./policies/", "policies/"} {
		t.Run(pluginPath, func(t *testing.T) {
			t.Chdir(t.TempDir())
			require.NoError(t, os.MkdirAll("policies", 0o755))
			require.NoError(t, os.WriteFile(filepath.Join("policies", "banner.rego"), []byte(vendorBanner), 0o644))
			resolve := func(_ context.Context, source string) (string, error) { return pluginPath, nil }

			override := func(id string) *Materialized {
				t.Helper()
				src := "package compliance_framework.banner\n\npolicy_id := \"" + id + "\"\n\ntitle := \"Banner\"\n"
				m, err := Materialize(context.Background(), testLayout(t.TempDir()), "b", &agentconfig.PolicyBundle{Extends: strptr("local"), Modules: map[string]string{"banner.rego": src}}, resolve)
				require.NoError(t, err)
				assert.Empty(t, OverrideStreams(m), "both continue the stream at the vendor's path")
				return m
			}
			assert.Empty(t, UnshadowedForks(override(pluginPath+"/banner.rego")), "the literal path continues the stream anywhere")
			assert.Equal(t, []string{"banner.rego"}, UnshadowedForks(override("policies/banner.rego")), "the cleaned path seeds a different _policy_path")
		})
	}
}
