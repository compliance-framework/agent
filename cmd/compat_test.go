package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/api/pkg/agentconfig"
)

// Plugin compatibility (R76, R88): the plugin's agent library decides whether it can
// evaluate set-form violations.

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
	const set = agentconfig.PolicyCodePluginLibViolationSetUnsupported
	vendorPolicies := strings.Replace(inlineBaseConfig, `policies: ["inline:ssh"]`, `policies: ["ghcr.io/vendor/policies:v1"]`, 1)
	trusted := strings.Replace(inlineBaseConfig, "mode: apply_safe", "mode: apply_safe\n  trusted_sources: [\"ghcr.io/compliance-framework/*\"]", 1)
	for _, tc := range []struct {
		name    string
		config  string
		libs    map[string]string // plugin source -> lib version; "*" for any other
		overlay string
		applied bool
		want    string // severity of the set-form problem at extra.rego ("" = none)
	}{
		{
			name: "overlay set form, lib v0.1.9", libs: map[string]string{"*": oldLib}, overlay: inlineOverlay,
			want: agentconfig.SeverityError,
		},
		{
			name: "overlay set form, lib v0.7.1", libs: map[string]string{"*": "v0.7.1"}, overlay: inlineOverlay, applied: true,
		},
		{
			name: "overlay set form, unknown lib", libs: map[string]string{"*": ""}, overlay: inlineOverlay, applied: true,
			want: agentconfig.SeverityWarning,
		},
		{
			name: "overlay assigns a set-form bundle, lib v0.7.2", config: vendorPolicies, libs: map[string]string{"*": "v0.7.2"},
			overlay: `{"plugins":{"ssh":{"policies":["inline:ssh"]}}}`, applied: true,
		},
		{
			name: "overlay assigns a set-form bundle, lib v0.7.0", config: vendorPolicies, libs: map[string]string{"*": "v0.7.0"},
			overlay: `{"plugins":{"ssh":{"policies":["inline:ssh"]}}}`,
			want:    agentconfig.SeverityError,
		},
		{
			name: "overlay moves the plugin to an old build", config: trusted,
			libs:    map[string]string{"ghcr.io/compliance-framework/plugin-ssh:v0": "v0.7.0", "*": "v0.9.0"},
			overlay: `{"plugins":{"ssh":{"source":"ghcr.io/compliance-framework/plugin-ssh:v0"}}}`,
			want:    agentconfig.SeverityError,
		},
		{
			name: "file set form, lib v0.7.0", libs: map[string]string{"*": "v0.7.0"}, applied: true,
			want: agentconfig.SeverityWarning,
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
			got := policyErrorsWithCode(r, set)
			if tc.want == agentconfig.SeverityError {
				got = rejectionErrors(r, set)
			}
			switch {
			case tc.want == "" && len(got) != 0:
				t.Fatalf("no %s expected, got %+v", set, got)
			case tc.want == "":
			case len(got) != 1 || got[0].Severity != tc.want || got[0].Path != "extra.rego" || got[0].Row == 0 || !strings.Contains(got[0].Message, "plugin ssh"):
				t.Fatalf("expected one located %s %s naming the plugin, got %+v", tc.want, set, r.PolicyErrors)
			case !strings.Contains(got[0].Message, "violation[{...}] if"):
				t.Fatalf("the set-form problem must name the fix: %s", got[0].Message)
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
	shadowed := &inlinepolicy.Materialized{Name: "b", Extends: &agentconfig.PolicyBundleExtendsReport{Source: "oci"}, Shadowed: true, SetViolations: set}
	absolute := &inlinepolicy.Materialized{Name: "b", Extends: &agentconfig.PolicyBundleExtendsReport{Source: "/abs"}, SetViolations: set}
	plain := &inlinepolicy.Materialized{Name: "b"}
	for _, tc := range []struct {
		name    string
		version string
		m       *inlinepolicy.Materialized
		overlay bool
		want    string // severity of the set-form problem, "" = none
	}{
		{"nothing to check, v0.1.9", oldLib, plain, true, ""},
		{"shadowed, v0.1.9", oldLib, shadowed, true, agentconfig.SeverityError},
		{"not shadowed, v0.1.9", oldLib, absolute, true, agentconfig.SeverityError},
		{"file, v0.1.9", oldLib, absolute, false, agentconfig.SeverityWarning},
		{"v0.7.2", "v0.7.2", absolute, true, ""},
		{"unknown", "", absolute, true, agentconfig.SeverityWarning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			for _, e := range libProblems("ssh", tc.version, []*inlinepolicy.Materialized{tc.m}, tc.overlay) {
				if e.Code != agentconfig.PolicyCodePluginLibViolationSetUnsupported {
					t.Fatalf("unexpected problem %+v", e)
				}
				got = e.Severity
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}

	untagged := libProblems("ssh", "v0.0.0-20261001110117-f88bde9ee37a", []*inlinepolicy.Materialized{absolute}, true)
	if len(untagged) != 1 || untagged[0].Severity != agentconfig.SeverityWarning || !strings.Contains(untagged[0].Message, "v0.0.0-20261001110117-f88bde9ee37a has no release before it") {
		t.Fatalf("an untagged build only warns and names its version, got %+v", untagged)
	}
}
