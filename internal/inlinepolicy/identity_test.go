package inlinepolicy

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentities(t *testing.T) {
	ids := Identities(map[string][]byte{
		"a.rego":       []byte("package compliance_framework.a\n\ntitle := \"a\"\n"),
		"a_extra.rego": []byte("package compliance_framework.a\n\ntitle2 := \"x\"\n"),
		"a_test.rego":  []byte("package compliance_framework.a\n\ntest_ok := true\n"),
		"b/b.rego":     []byte("package compliance_framework.b\n\ntitle := \"b\"\n"),
		"lib.rego":     []byte("package ccf_libs.helpers\n\nyes := true\n"),
		"broken.rego":  []byte("package compliance_framework.broken\n\ntitle := \n"),
		"data.json":    []byte("{}"),
	})
	assert.Equal(t, []ModuleIdentity{
		{Path: "a.rego", Package: "compliance_framework.a"},
		{Path: "a_extra.rego", Package: "compliance_framework.a"},
		{Path: "b/b.rego", Package: "compliance_framework.b"},
	}, ids)
}

func TestSetViolationSites(t *testing.T) {
	files := map[string][]byte{
		"set.rego":      []byte("package compliance_framework.set\n\nimport rego.v1\n\nviolation contains {\"id\": \"x\"} if input.bad\n"),
		"object.rego":   []byte("package compliance_framework.object\n\nimport rego.v1\n\nviolation[{\"id\": \"x\"}] if input.bad\n"),
		"vendor.rego":   []byte("package compliance_framework.vendor\n\nimport rego.v1\n\nviolation contains {\"id\": \"x\"} if input.bad\n"),
		"set_test.rego": []byte("package compliance_framework.set\n\nimport rego.v1\n\nviolation contains 1 if true\n"),
	}
	set := setViolationSites(files, map[string]bool{"set.rego": true, "object.rego": true, "set_test.rego": true})
	assert.Equal(t, []Site{{Path: "set.rego", Row: 5, Col: 1}}, set, "only authored set-form violations; the object form works with every plugin")
}

// TestOverrideStreams_R75: an override continues the vendor module's stream at the vendor's
// path unless it changes the package. Served at the bundle's own path (not shadowed), the
// modules that keep the vendor's package are UnshadowedForks.
func TestOverrideStreams_R75(t *testing.T) {
	_, resolve := vendorTree(t, map[string]string{"banner.rego": vendorBanner, "max_auth.rego": vendorMaxAuth})
	cases := []struct {
		name    string
		modules map[string]string
		want    map[string]string // path -> code
		forks   []string
	}{
		{"changed override", map[string]string{"banner.rego": vendorBanner + "\n# changed\n"}, map[string]string{}, []string{"banner.rego", "max_auth.rego"}},
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
