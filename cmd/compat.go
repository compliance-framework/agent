package cmd

import (
	"context"
	"fmt"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/agent/internal/pluginlib"
	"github.com/compliance-framework/api/pkg/agentconfig"
)

// Plugin compatibility (R76, R79, relaxed by path shadowing). A plugin evaluates policies
// with the policy-manager it embeds, so what it can do with an inline bundle depends on the
// agent library it was built with, which the agent reads from the plugin binary's build info.
// With path shadowing (shadow.go) a plugin keeps the vendor's evidence streams of a bundle
// that extends a relative (OCI) source whatever library it was built with, so the R79 gate
// only remains where continuity cannot be guaranteed otherwise:
//
//   - a bundle that extends a source and is not shadowed (an absolute local extends path,
//     a plugin that also loads the source, no symlinks) keeps the vendor streams only
//     through the continuity policy_id (R82), which needs pluginlib.MinInlinePolicy (R74).
//     For an older library an overlay that introduces it is rejected
//     (plugin-lib-inline-unsupported), so the last good configuration keeps running;
//   - a set-form violation (`violation contains ...`) crashes plugins older than
//     pluginlib.MinViolationSet: rejected when the overlay introduces it
//     (plugin-lib-violation-set-unsupported);
//   - a policy_id an authored module declares is ignored by an older library, so the
//     module's stream is path-based: a warning (plugin-lib-policy-id-unsupported);
//   - inline bundles from the config file only warn (R34), and so does a library whose
//     version is unknown (a local or replaced build, or no build info).
//
// plugins[].inline-policies now reads: supported (the library version is known, so the agent
// checks each bundle against it as above) or unknown; unsupported is no longer reported.

// Shorter names for the plugins[].inline-policies values (R79).
const (
	inlinePoliciesSupported   = agentconfig.InlinePoliciesSupported
	inlinePoliciesUnsupported = agentconfig.InlinePoliciesUnsupported
	inlinePoliciesUnknown     = agentconfig.InlinePoliciesUnknown
)

// pluginLibFunc returns the agent library version the binary of a plugin source was built
// with ("" when unknown). The source has been prefetched.
type pluginLibFunc func(ctx context.Context, source string) (string, error)

// inlineSupport classifies a plugin's agent library version for inline policies: with path
// shadowing every known library takes inline bundles (each bundle is checked against it).
func inlineSupport(version string) string {
	if _, known := pluginlib.AtLeast(version, pluginlib.MinInlinePolicy); !known {
		return inlinePoliciesUnknown
	}
	return inlinePoliciesSupported
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
		if ok, _ := pluginlib.AtLeast(version, pluginlib.MinInlinePolicy); ok {
			continue // policy_id and set-form violations both work
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
		problems = append(problems, libProblems(name, version, bundles, introduced)...)
	}
	return problems, reports
}

// needsPolicyID reports whether bundle m keeps vendor evidence streams only through the
// continuity policy_id the agent appended (R82): it extends a source and is not shadowed.
func needsPolicyID(m *inlinepolicy.Materialized) bool {
	return m.Extends != nil && !m.Shadowed && len(m.Continued) > 0
}

// libProblems are the problems of one plugin whose library is older than
// pluginlib.MinInlinePolicy or unknown. overlay is whether the overlay brought the plugin and
// these bundles together; only then is a known incompatibility an error.
func libProblems(plugin, version string, bundles []*inlinepolicy.Materialized, overlay bool) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	lib := version
	if lib == "" {
		lib = "unknown"
	}
	idOK, known := pluginlib.AtLeast(version, pluginlib.MinInlinePolicy)
	setOK, setKnown := pluginlib.AtLeast(version, pluginlib.MinViolationSet)
	severity := func(known bool) string {
		if known && overlay {
			return agentconfig.SeverityError
		}
		return agentconfig.SeverityWarning
	}
	unknownWhy := "is unknown (a local or replaced build, or no build info)"
	if version != "" {
		unknownWhy = fmt.Sprintf("%s has no release before it", version)
	}
	for _, m := range bundles {
		if !idOK && needsPolicyID(m) {
			msg := fmt.Sprintf("plugin %s (agent lib %s) cannot keep the vendor evidence streams of bundle %s: it extends %s at %s, which cannot be shadowed, so its inherited and overridden modules continue the vendor streams only through policy_id, which needs agent ≥ %s; upgrade the plugin, or extend a relative (OCI) source the plugin does not also load",
				plugin, lib, m.Name, m.Extends.Source, m.Extends.PluginPath, pluginlib.MinInlinePolicy)
			if !known {
				msg = fmt.Sprintf("plugin %s: its agent library version %s, so the agent cannot tell whether it honours the policy_id that continues the vendor streams of bundle %s (it extends %s at %s, which cannot be shadowed); plugins built on agent < %s ignore it and start new streams",
					plugin, unknownWhy, m.Name, m.Extends.Source, m.Extends.PluginPath, pluginlib.MinInlinePolicy)
			}
			out = append(out, agentconfig.PolicyError{Bundle: m.Name, Severity: severity(known), Code: agentconfig.PolicyCodePluginLibInlineUnsupported, Message: msg})
		}
		if !setOK {
			for _, s := range m.SetViolations {
				msg := fmt.Sprintf("plugin %s (agent lib %s) cannot evaluate violation as a set (`violation contains ...` needs agent ≥ %s) and would crash; use `violation[{...}] if { … }`",
					plugin, lib, pluginlib.MinViolationSet)
				if !setKnown {
					msg = fmt.Sprintf("plugin %s: its agent library version %s; plugins built on agent < %s crash on `violation contains ...`; use `violation[{...}] if { … }`",
						plugin, unknownWhy, pluginlib.MinViolationSet)
				}
				out = append(out, agentconfig.PolicyError{Bundle: m.Name, Path: s.Path, Row: s.Row, Col: s.Col, Severity: severity(setKnown),
					Code: agentconfig.PolicyCodePluginLibViolationSetUnsupported, Message: msg})
			}
		}
		if !idOK && known {
			for _, s := range m.PolicyIDRules {
				out = append(out, agentconfig.PolicyError{Bundle: m.Name, Path: s.Path, Row: s.Row, Col: s.Col, Severity: agentconfig.SeverityWarning,
					Code:    agentconfig.PolicyCodePluginLibPolicyIDUnsupported,
					Message: fmt.Sprintf("plugin %s (agent lib %s) ignores policy_id; this module's evidence stream follows its path", plugin, lib)})
			}
		}
	}
	return out
}
