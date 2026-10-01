package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/compliance-framework/agent/internal/pluginlib"
	"github.com/compliance-framework/api/pkg/agentconfig"
)

// Plugin compatibility (R76, R79): the plugin's agent library decides whether it may use
// inline policies.

// withPluginLib makes the harness's plugins report version as their agent library.
func withPluginLib(h *remoteHarness, version string) {
	h.rc.pluginLib = func(context.Context, string) (string, error) { return version, nil }
}

// inlineOverlay changes the inline bundle ssh, which plugin ssh uses (an overlay-introduced
// inline policy).
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

func TestCompat_OldLibRejectsOverlayInlineBundle_R79(t *testing.T) {
	h, _ := newInlineHarness(t)
	withPluginLib(h, "v0.1.9-0.20250708121809-c5059c3efac8")
	h.remote.publish(1, inlineOverlay)
	active := mustStartup(t, h.rc)
	if active.overlay != nil {
		t.Fatal("an inline bundle for a plugin that cannot honour it must not be applied")
	}
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusRejected || r.Reason != agentconfig.ReasonPolicyErrors {
		t.Fatalf("expected rejected/policy-errors, got %s/%s", r.Status, r.Reason)
	}
	gate := rejectionErrors(r, agentconfig.PolicyCodePluginLibInlineUnsupported)
	if len(gate) != 1 || gate[0].Bundle != "ssh" ||
		!strings.Contains(gate[0].Message, "plugin ssh (agent lib v0.1.9-0.20250708121809-c5059c3efac8) doesn't support inline policies") ||
		!strings.Contains(gate[0].Message, pluginlib.MinInlinePolicy) {
		t.Fatalf("expected one plugin-lib-inline-unsupported error naming the plugin, its lib and the minimum, got %+v", r.PolicyErrors)
	}
	// The more specific set-form problem is named too, with its fix.
	set := rejectionErrors(r, agentconfig.PolicyCodePluginLibViolationSetUnsupported)
	if len(set) != 1 || set[0].Path != "extra.rego" || set[0].Row == 0 ||
		!strings.Contains(set[0].Message, "violation[{...}] if") {
		t.Fatalf("expected a located set-form violation error, got %+v", r.PolicyErrors)
	}
	// The gate supersedes the policy_id warning for overlay bundles.
	if got := policyErrorsWithCode(r, agentconfig.PolicyCodePluginLibPolicyIDUnsupported); len(got) != 0 {
		t.Fatalf("no policy_id warning expected next to the gate, got %+v", got)
	}
	if len(r.Plugins) != 1 || r.Plugins[0].Name != "ssh" || r.Plugins[0].Source != "ghcr.io/compliance-framework/plugin-ssh:v1" ||
		r.Plugins[0].LibVersion != "v0.1.9-0.20250708121809-c5059c3efac8" || r.Plugins[0].InlinePolicies != agentconfig.InlinePoliciesUnsupported {
		t.Fatalf("plugins report = %+v", r.Plugins)
	}
}

func TestCompat_AssigningInlineBundleToOldLibIsRejected_R79(t *testing.T) {
	h, _ := newInlineHarnessWith(t, strings.Replace(inlineBaseConfig, `policies: ["inline:ssh"]`, `policies: ["ghcr.io/vendor/policies:v1"]`, 1))
	withPluginLib(h, "v0.7.2")
	h.remote.publish(1, `{"plugins":{"ssh":{"policies":["inline:ssh"]}}}`)
	active := mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if active.overlay != nil || r.Status != agentconfig.StatusRejected {
		t.Fatalf("assigning an inline bundle to a v0.7.2 plugin must be rejected, got %s/%s", r.Status, r.Reason)
	}
	if gate := rejectionErrors(r, agentconfig.PolicyCodePluginLibInlineUnsupported); len(gate) != 1 {
		t.Fatalf("expected the plugin-lib-inline-unsupported error, got %+v", r.PolicyErrors)
	}
	// v0.7.2 evaluates set-form violations: no set-form error.
	if set := rejectionErrors(r, agentconfig.PolicyCodePluginLibViolationSetUnsupported); len(set) != 0 {
		t.Fatalf("no set-form error expected for v0.7.2, got %+v", set)
	}
}

func TestCompat_SupportedLibApplies_R79(t *testing.T) {
	h, _ := newInlineHarness(t)
	withPluginLib(h, "v0.9.0")
	h.remote.publish(1, inlineOverlay)
	active := mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if active.overlay == nil || r.Status != agentconfig.StatusApplied {
		t.Fatalf("a supported plugin must apply the revision, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
	}
	for _, code := range []string{agentconfig.PolicyCodePluginLibInlineUnsupported, agentconfig.PolicyCodePluginLibViolationSetUnsupported, agentconfig.PolicyCodePluginLibPolicyIDUnsupported} {
		if got := policyErrorsWithCode(r, code); len(got) != 0 {
			t.Fatalf("no %s expected for a supported plugin, got %+v", code, got)
		}
	}
	if len(r.Plugins) != 1 || r.Plugins[0].LibVersion != "v0.9.0" || r.Plugins[0].InlinePolicies != agentconfig.InlinePoliciesSupported {
		t.Fatalf("plugins report = %+v", r.Plugins)
	}
}

func TestCompat_UnknownLibAppliesWithWarnings_R79(t *testing.T) {
	// A local build with a replace (the RC stack's plugin-local-ssh) or "(devel)": the
	// library version is unknown.
	h, _ := newInlineHarness(t)
	withPluginLib(h, "")
	h.remote.publish(1, inlineOverlay)
	active := mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if active.overlay == nil || r.Status != agentconfig.StatusApplied {
		t.Fatalf("an unknown library must not block, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
	}
	gate := policyErrorsWithCode(r, agentconfig.PolicyCodePluginLibInlineUnsupported)
	if len(gate) != 1 || gate[0].Severity != agentconfig.SeverityWarning || !strings.Contains(gate[0].Message, "unknown") {
		t.Fatalf("expected a plugin-lib-inline-unsupported warning, got %+v", r.PolicyErrors)
	}
	set := policyErrorsWithCode(r, agentconfig.PolicyCodePluginLibViolationSetUnsupported)
	if len(set) != 1 || set[0].Severity != agentconfig.SeverityWarning {
		t.Fatalf("expected a set-form warning, got %+v", r.PolicyErrors)
	}
	if len(r.Plugins) != 1 || r.Plugins[0].LibVersion != "" || r.Plugins[0].InlinePolicies != agentconfig.InlinePoliciesUnknown {
		t.Fatalf("plugins report = %+v", r.Plugins)
	}
}

func TestCompat_FileInlineBundleOnOldLibWarns_R79(t *testing.T) {
	h, _ := newInlineHarnessWith(t, strings.Replace(inlineBaseConfig, "        title := \"extra\"\n", "        policy_id := \"extra\"\n\n        title := \"extra\"\n", 1))
	withPluginLib(h, "v0.7.2")
	active := mustStartup(t, h.rc)
	if active == nil {
		t.Fatal("a file-defined inline bundle must still load")
	}
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusApplied && r.Status != agentconfig.StatusNotApplicable {
		t.Fatalf("file-origin problems only warn, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
	}
	gate := policyErrorsWithCode(r, agentconfig.PolicyCodePluginLibInlineUnsupported)
	if len(gate) != 1 || gate[0].Severity != agentconfig.SeverityWarning {
		t.Fatalf("expected a plugin-lib-inline-unsupported warning, got %+v", r.PolicyErrors)
	}
	ids := policyErrorsWithCode(r, agentconfig.PolicyCodePluginLibPolicyIDUnsupported)
	if len(ids) != 1 || ids[0].Severity != agentconfig.SeverityWarning || ids[0].Path != "extra.rego" {
		t.Fatalf("expected a plugin-lib-policy-id-unsupported warning for the file bundle, got %+v", r.PolicyErrors)
	}
}

func TestInlineSupport(t *testing.T) {
	for version, want := range map[string]string{
		"v0.9.0":                             inlinePoliciesSupported,
		"v0.9.0-rc1":                         inlinePoliciesSupported,
		"v0.8.0":                             inlinePoliciesUnsupported,
		"v0.7.1":                             inlinePoliciesUnsupported,
		"":                                   inlinePoliciesUnknown,
		"(devel)":                            inlinePoliciesUnknown,
		"v0.0.0-20261001110117-f88bde9ee37a": inlinePoliciesUnknown,
	} {
		if got := inlineSupport(version); got != want {
			t.Errorf("inlineSupport(%q) = %s, want %s", version, got, want)
		}
	}
}
