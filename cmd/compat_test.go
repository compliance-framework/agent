package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/api/pkg/agentconfig"
)

// Plugin compatibility (R76, R88): the plugin's agent library decides whether it can
// evaluate set-form violations, and whether it honours an authored policy_id.

// withPluginLib makes the harness's plugins report version as their agent library.
func withPluginLib(h *remoteHarness, version string) {
	h.rc.pluginLib = func(context.Context, string) (string, error) { return version, nil }
}

// inlineOverlay changes the inline bundle ssh, which plugin ssh uses (an overlay-introduced
// inline policy), with a set-form violation.
const inlineOverlay = `{"policy_bundles":{"ssh":{"modules":{"extra.rego":"package compliance_framework.extra\n\nimport rego.v1\n\ntitle := \"extra v2\"\n\nviolation contains {\"id\": \"x\"} if input.max > data.max\n"}}}}`

func policyErrorsWithCode(r agentconfig.Report, code string) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	for _, e := range r.PolicyErrors {
		if e.Code == code {
			out = append(out, e)
		}
	}
	return out
}

// rejectionErrors are the report's errors: a rejected revision's report also carries the
// running configuration's warnings.
func rejectionErrors(r agentconfig.Report, code string) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	for _, e := range policyErrorsWithCode(r, code) {
		if e.Severity == agentconfig.SeverityError {
			out = append(out, e)
		}
	}
	return out
}

func TestCompat(t *testing.T) {
	const (
		set = agentconfig.PolicyCodePluginLibViolationSetUnsupported
		id  = agentconfig.PolicyCodePluginLibPolicyIDUnsupported
	)
	vendorPolicies := strings.Replace(inlineBaseConfig, `policies: ["inline:ssh"]`, `policies: ["ghcr.io/vendor/policies:v1"]`, 1)
	withPolicyID := strings.Replace(inlineBaseConfig, "        title := \"extra\"\n", "        policy_id := \"extra\"\n\n        title := \"extra\"\n", 1)
	trusted := strings.Replace(inlineBaseConfig, "mode: apply_safe", "mode: apply_safe\n  trusted_sources: [\"ghcr.io/compliance-framework/*\"]", 1)
	for _, tc := range []struct {
		name    string
		config  string
		libs    map[string]string // plugin source -> lib version; "*" for any other
		overlay string
		applied bool
		want    map[string]string // code -> severity of its problems at extra.rego ("" = none)
	}{
		{
			name: "overlay set form, lib v0.1.9", libs: map[string]string{"*": oldLib}, overlay: inlineOverlay,
			want: map[string]string{set: agentconfig.SeverityError},
		},
		{
			name: "overlay set form, lib v0.9.0", libs: map[string]string{"*": "v0.9.0"}, overlay: inlineOverlay, applied: true,
		},
		{
			name: "overlay set form, unknown lib", libs: map[string]string{"*": ""}, overlay: inlineOverlay, applied: true,
			want: map[string]string{set: agentconfig.SeverityWarning},
		},
		{
			name: "overlay assigns a set-form bundle, lib v0.7.2", config: vendorPolicies, libs: map[string]string{"*": "v0.7.2"},
			overlay: `{"plugins":{"ssh":{"policies":["inline:ssh"]}}}`, applied: true,
		},
		{
			name: "overlay assigns a set-form bundle, lib v0.7.0", config: vendorPolicies, libs: map[string]string{"*": "v0.7.0"},
			overlay: `{"plugins":{"ssh":{"policies":["inline:ssh"]}}}`,
			want:    map[string]string{set: agentconfig.SeverityError},
		},
		{
			name: "overlay moves the plugin to an old build", config: trusted,
			libs:    map[string]string{"ghcr.io/compliance-framework/plugin-ssh:v0": "v0.7.0", "*": "v0.9.0"},
			overlay: `{"plugins":{"ssh":{"source":"ghcr.io/compliance-framework/plugin-ssh:v0"}}}`,
			want:    map[string]string{set: agentconfig.SeverityError},
		},
		{
			name: "file policy_id and set form, lib v0.7.0", config: withPolicyID, libs: map[string]string{"*": "v0.7.0"}, applied: true,
			want: map[string]string{set: agentconfig.SeverityWarning, id: agentconfig.SeverityWarning},
		},
		{
			name: "overlay policy_id, lib v0.8.1", libs: map[string]string{"*": "v0.8.1"}, applied: true,
			overlay: `{"policy_bundles":{"ssh":{"modules":{"extra.rego":"package compliance_framework.extra\n\nimport rego.v1\n\npolicy_id := \"extra\"\n\ntitle := \"extra v2\"\n\nviolation[{\"id\": \"x\"}] if input.max > data.max\n"}}}}`,
			want:    map[string]string{id: agentconfig.SeverityWarning},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config
			if config == "" {
				config = inlineBaseConfig
			}
			h, _ := newInlineHarnessWith(t, config)
			lib := func(source string) string {
				if v, ok := tc.libs[source]; ok {
					return v
				}
				return tc.libs["*"]
			}
			h.rc.pluginLib = func(_ context.Context, source string) (string, error) { return lib(source), nil }
			if tc.overlay != "" {
				h.remote.publish(1, tc.overlay)
			}
			active := mustStartup(t, h.rc)
			r := h.remote.lastReport(t)
			switch {
			case tc.overlay == "" && r.Status != agentconfig.StatusApplied && r.Status != agentconfig.StatusNotApplicable:
				t.Fatalf("the file configuration must load, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
			case tc.overlay != "" && tc.applied && (active.overlay == nil || r.Status != agentconfig.StatusApplied):
				t.Fatalf("expected applied, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
			case !tc.applied && (active.overlay != nil || r.Status != agentconfig.StatusRejected || r.Reason != agentconfig.ReasonPolicyErrors):
				t.Fatalf("expected rejected/policy-errors, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
			}
			for _, code := range []string{set, id} {
				got := policyErrorsWithCode(r, code)
				if tc.want[code] == agentconfig.SeverityError {
					got = rejectionErrors(r, code)
				}
				switch {
				case tc.want[code] == "" && len(got) != 0:
					t.Fatalf("no %s expected, got %+v", code, got)
				case tc.want[code] == "":
				case len(got) != 1 || got[0].Severity != tc.want[code] || got[0].Path != "extra.rego" || got[0].Row == 0 || !strings.Contains(got[0].Message, "plugin ssh"):
					t.Fatalf("expected one located %s %s naming the plugin, got %+v", tc.want[code], code, r.PolicyErrors)
				case code == set && !strings.Contains(got[0].Message, "violation[{...}] if"):
					t.Fatalf("the set-form problem must name the fix: %s", got[0].Message)
				}
			}
			if len(r.Plugins) != 1 || r.Plugins[0].Name != "ssh" || r.Plugins[0].LibVersion != lib(r.Plugins[0].Source) {
				t.Fatalf("plugins report = %+v", r.Plugins)
			}
		})
	}
}

// TestLibProblems: per plugin library and origin, for any bundle (shadowed or not).
func TestLibProblems(t *testing.T) {
	set := []inlinepolicy.Site{{Path: "s.rego", Row: 1, Col: 1}}
	ids := []inlinepolicy.Site{{Path: "i.rego", Row: 1, Col: 1}}
	shadowed := &inlinepolicy.Materialized{Name: "b", Extends: &agentconfig.PolicyBundleExtendsReport{Source: "oci"}, Shadowed: true, SetViolations: set, PolicyIDRules: ids}
	absolute := &inlinepolicy.Materialized{Name: "b", Extends: &agentconfig.PolicyBundleExtendsReport{Source: "/abs"}, SetViolations: set, PolicyIDRules: ids}
	plain := &inlinepolicy.Materialized{Name: "b"}
	type want struct{ set, id string } // severity of each code, "" = none
	for _, tc := range []struct {
		name    string
		version string
		m       *inlinepolicy.Materialized
		overlay bool
		want    want
	}{
		{"nothing to check, v0.1.9", oldLib, plain, true, want{}},
		{"shadowed, v0.1.9", oldLib, shadowed, true, want{set: agentconfig.SeverityError, id: agentconfig.SeverityWarning}},
		{"not shadowed, v0.1.9", oldLib, absolute, true, want{set: agentconfig.SeverityError, id: agentconfig.SeverityWarning}},
		{"file, v0.1.9", oldLib, absolute, false, want{set: agentconfig.SeverityWarning, id: agentconfig.SeverityWarning}},
		{"v0.7.2", "v0.7.2", absolute, true, want{id: agentconfig.SeverityWarning}},
		{"v0.9.0-rc1", "v0.9.0-rc1", absolute, true, want{id: agentconfig.SeverityWarning}},
		{"unknown", "", absolute, true, want{set: agentconfig.SeverityWarning}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got want
			for _, e := range libProblems("ssh", tc.version, []*inlinepolicy.Materialized{tc.m}, tc.overlay) {
				switch e.Code {
				case agentconfig.PolicyCodePluginLibViolationSetUnsupported:
					got.set = e.Severity
				case agentconfig.PolicyCodePluginLibPolicyIDUnsupported:
					got.id = e.Severity
				default:
					t.Fatalf("unexpected problem %+v", e)
				}
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}

	untagged := libProblems("ssh", "v0.0.0-20261001110117-f88bde9ee37a", []*inlinepolicy.Materialized{absolute}, true)
	if len(untagged) != 1 || untagged[0].Severity != agentconfig.SeverityWarning || !strings.Contains(untagged[0].Message, "v0.0.0-20261001110117-f88bde9ee37a has no release before it") {
		t.Fatalf("an untagged build only warns and names its version, got %+v", untagged)
	}
}
