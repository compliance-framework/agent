package cmd

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/agent/internal/pluginlib"
	"github.com/compliance-framework/api/pkg/agentconfig"
)

// Plugin compatibility (R76, R88). A plugin evaluates policies with the policy-manager it
// embeds, so what it can do with an inline bundle depends on the agent library it was built
// with, which the agent reads from the plugin binary's build info. Path shadowing
// (shadow.go) keeps vendor evidence streams with any library, so only two things depend on
// it:
//
//   - a set-form violation (`violation contains ...`) crashes plugins older than
//     pluginlib.MinViolationSet: an error when the overlay introduces it
//     (plugin-lib-violation-set-unsupported);
//   - a policy_id an authored module declares is ignored by plugins older than
//     pluginlib.MinPolicyID, so the module's stream is path-based: a warning
//     (plugin-lib-policy-id-unsupported).
//
// Inline bundles from the config file only warn (R34), and so does a library whose version
// is unknown (a local or replaced build, or no build info). The plugins report carries each
// plugin's lib-version.

// pluginLibFunc returns the agent library version the binary of a plugin source was built
// with ("" when unknown). The source has been prefetched.
type pluginLibFunc func(ctx context.Context, source string) (string, error)

// pluginCompatibility returns the R76 problems of the plugins of runtime that use inline
// bundles, and the plugins report. origin tells overlay-introduced problems apart. Without a
// pluginLib function (tests) it checks and reports nothing.
func (rc *reconciler) pluginCompatibility(ctx context.Context, runtime *agentConfig, materialized map[string]*inlinepolicy.Materialized, origin policyOrigin) ([]agentconfig.PolicyError, []agentconfig.PluginReport) {
	if rc.pluginLib == nil || runtime == nil {
		return nil, nil
	}
	var problems []agentconfig.PolicyError
	var reports []agentconfig.PluginReport
	for _, name := range slices.Sorted(maps.Keys(runtime.Plugins)) {
		p := runtime.Plugins[name]
		version, err := rc.pluginLib(ctx, p.Source)
		if err != nil {
			version = ""
			if rc.logOnce("plugin-lib\x00" + p.Source + "\x00" + err.Error()) {
				rc.logger.Warn("Could not read the agent library version of a plugin; treating it as unknown", "plugin", name, "source", p.Source, "error", err)
			}
		}
		reports = append(reports, agentconfig.PluginReport{Name: name, Source: p.Source, LibVersion: version})
		if ok, _ := pluginlib.AtLeast(version, pluginlib.MinPolicyID); ok {
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

// libProblems are the problems of one plugin whose library is older than
// pluginlib.MinPolicyID or unknown. overlay is whether the overlay brought the plugin and
// these bundles together; only then is a known incompatibility an error.
func libProblems(plugin, version string, bundles []*inlinepolicy.Materialized, overlay bool) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	lib := version
	if lib == "" {
		lib = "unknown"
	}
	idOK, known := pluginlib.AtLeast(version, pluginlib.MinPolicyID)
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
