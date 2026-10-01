package cmd

import (
	"context"
	"fmt"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/agent/internal/pluginlib"
	"github.com/compliance-framework/api/pkg/agentconfig"
)

// Plugin compatibility (R76, R79). A plugin evaluates policies with the policy-manager it
// embeds, so what it can do with an inline bundle depends on the agent library it was built
// with, which the agent reads from the plugin binary's build info:
//
//   - inline policies need pluginlib.MinInlinePolicy, the first library that seeds evidence
//     with policy_id (R74). An overlay that gives a plugin built on an older library an
//     inline bundle, changes one it uses, or moves a plugin that uses one to such a build
//     is rejected (plugin-lib-inline-unsupported), so the last good configuration keeps
//     running (R79);
//   - a set-form violation (`violation contains ...`) crashes plugins older than
//     pluginlib.MinViolationSet, which is named separately when it applies, with the fix;
//   - inline bundles from the config file only warn (R34), and so does a library whose
//     version is unknown (a local or replaced build, or no build info), so local plugin
//     builds keep working. For file bundles a policy_id that the plugin ignores is named per
//     module (plugin-lib-policy-id-unsupported); for overlay bundles the gate supersedes it.

// Shorter names for the plugins[].inline-policies values (R79).
const (
	inlinePoliciesSupported   = agentconfig.InlinePoliciesSupported
	inlinePoliciesUnsupported = agentconfig.InlinePoliciesUnsupported
	inlinePoliciesUnknown     = agentconfig.InlinePoliciesUnknown
)

// pluginLibFunc returns the agent library version the binary of a plugin source was built
// with ("" when unknown). The source has been prefetched.
type pluginLibFunc func(ctx context.Context, source string) (string, error)

// inlineSupport classifies a plugin's agent library version for inline policies.
func inlineSupport(version string) string {
	ok, known := pluginlib.AtLeast(version, pluginlib.MinInlinePolicy)
	switch {
	case !known:
		return inlinePoliciesUnknown
	case ok:
		return inlinePoliciesSupported
	default:
		return inlinePoliciesUnsupported
	}
}

// pluginCompatibility returns the R76/R79 problems of the plugins of runtime that use inline
// bundles, and the plugins report. origin tells overlay-introduced problems apart. Without a
// pluginLib function (tests) it checks and reports nothing.
func (rc *reconciler) pluginCompatibility(ctx context.Context, runtime *agentConfig, materialized map[string]*inlinepolicy.Materialized, origin policyOrigin) ([]agentconfig.PolicyError, []agentconfig.PluginReport) {
	if rc.pluginLib == nil || runtime == nil {
		return nil, nil
	}
	var problems []agentconfig.PolicyError
	var reports []agentconfig.PluginReport
	for _, name := range sortedMapKeys(runtime.Plugins) {
		p := runtime.Plugins[name]
		version, err := rc.pluginLib(ctx, p.Source)
		if err != nil {
			version = ""
			if rc.logOnce("plugin-lib\x00" + p.Source + "\x00" + err.Error()) {
				rc.logger.Warn("Could not read the agent library version of a plugin; treating it as unknown", "plugin", name, "source", p.Source, "error", err)
			}
		}
		support := inlineSupport(version)
		reports = append(reports, agentconfig.PluginReport{Name: name, Source: p.Source, LibVersion: version, InlinePolicies: support})
		if support == inlinePoliciesSupported {
			continue
		}

		var bundles []*inlinepolicy.Materialized
		seen := map[string]bool{}
		// The overlay brought the plugin and its inline policies together when it changed the
		// plugin's source (a different build), gave it an inline entry, or changed a bundle
		// it uses.
		introduced := origin.pluginTouched(name, "source")
		for _, e := range p.Policies {
			if b, ok := agentconfig.InlineBundleName(string(e)); ok && materialized[b] != nil && !seen[b] {
				seen[b] = true
				bundles = append(bundles, materialized[b])
				introduced = introduced || origin.newEntry(name, string(e)) || origin.bundleTouched(b)
			}
		}
		if len(bundles) == 0 {
			continue
		}
		problems = append(problems, libProblems(name, version, support, bundles, introduced)...)
	}
	return problems, reports
}

// libProblems are the problems of one plugin whose library is not known to support inline
// policies (support is unsupported or unknown).
func libProblems(plugin, version, support string, bundles []*inlinepolicy.Materialized, overlay bool) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	lib := version
	if lib == "" {
		lib = "unknown"
	}
	severity := agentconfig.SeverityWarning
	if support == inlinePoliciesUnsupported && overlay {
		severity = agentconfig.SeverityError
	}
	setOK, setKnown := pluginlib.AtLeast(version, pluginlib.MinViolationSet)
	for _, m := range bundles {
		msg := fmt.Sprintf("plugin %s (agent lib %s) doesn't support inline policies; upgrade the plugin to a build on agent ≥ %s", plugin, lib, pluginlib.MinInlinePolicy)
		if support == inlinePoliciesUnknown {
			why := "is unknown (a local or replaced build, or no build info)"
			if version != "" {
				why = fmt.Sprintf("%s has no release before it", version)
			}
			msg = fmt.Sprintf("plugin %s: its agent library version %s, so the agent cannot tell whether it supports inline policies; plugins built on agent < %s ignore policy_id, and those < %s crash on `violation contains ...`",
				plugin, why, pluginlib.MinInlinePolicy, pluginlib.MinViolationSet)
		}
		out = append(out, agentconfig.PolicyError{Bundle: m.Name, Severity: severity, Code: agentconfig.PolicyCodePluginLibInlineUnsupported, Message: msg})

		if !setOK {
			sev := severity
			if !setKnown {
				sev = agentconfig.SeverityWarning
			}
			for _, s := range m.SetViolations {
				out = append(out, agentconfig.PolicyError{Bundle: m.Name, Path: s.Path, Row: s.Row, Col: s.Col, Severity: sev,
					Code: agentconfig.PolicyCodePluginLibViolationSetUnsupported,
					Message: fmt.Sprintf("plugin %s (agent lib %s) cannot evaluate violation as a set (`violation contains ...` needs agent ≥ %s) and would crash; use `violation[{...}] if { … }`",
						plugin, lib, pluginlib.MinViolationSet)})
			}
		}
		if support == inlinePoliciesUnsupported && !overlay {
			for _, s := range m.PolicyIDRules {
				out = append(out, agentconfig.PolicyError{Bundle: m.Name, Path: s.Path, Row: s.Row, Col: s.Col, Severity: agentconfig.SeverityWarning,
					Code:    agentconfig.PolicyCodePluginLibPolicyIDUnsupported,
					Message: fmt.Sprintf("plugin %s (agent lib %s) ignores policy_id; this module starts a new evidence stream", plugin, lib)})
			}
		}
	}
	return out
}
