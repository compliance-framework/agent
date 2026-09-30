package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"sort"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/agentconfig/regocheck"
)

// inlineGCKeepPerBundle is how many materialized versions of each bundle GC keeps besides the
// active ones.
const inlineGCKeepPerBundle = 5

// inlineRoot is where inline bundles are materialized (under the state dir, R31).
func (rc *reconciler) inlineRoot() string {
	return filepath.Join(rc.store.Dir(), "inline")
}

// prepareInline is prepare step 8 (G3b): the parse-level checks on every bundle, then
// materialize each bundle an enabled plugin references and check it per (plugin, path) the
// way the plugin will load it. Any error rejects the revision (policy-errors); warnings are
// kept for the report. No network is touched before the Classify gate: extends trees are
// fetched here, after it.
func (rc *reconciler) prepareInline(ctx context.Context, resolved agentconfig.Config, skip map[string]string) (inlineResult, *applyError) {
	var res inlineResult
	if len(resolved.PolicyBundles) == 0 {
		return res, nil
	}

	static := regocheck.ValidatePolicyBundles(resolved.PolicyBundles)
	if agentconfig.HasPolicyErrors(static) {
		return res, policyRejection(static)
	}
	res.warnings = append(res.warnings, static...)

	// Bundles referenced by the plugins that will run.
	refs := map[string]bool{}
	for name, p := range resolved.Plugins {
		if p == nil || !p.IsEnabled() {
			continue
		}
		if _, skipped := skip[name]; skipped {
			continue
		}
		for _, e := range p.Policies {
			if b, ok := agentconfig.InlineBundleName(e); ok {
				refs[b] = true
			}
		}
	}
	if len(refs) == 0 {
		return res, nil
	}

	materialized := map[string]*inlinepolicy.Materialized{}
	var problems []agentconfig.PolicyError
	for _, name := range sortedBoolKeys(refs) {
		m, err := inlinepolicy.Materialize(ctx, rc.inlineRoot(), name, resolved.PolicyBundles[name], rc.boundedResolver())
		var perrs inlinepolicy.PolicyErrors
		switch {
		case errors.As(err, &perrs):
			problems = append(problems, perrs...)
			continue
		case errors.Is(err, inlinepolicy.ErrResolve):
			return res, failed(agentconfig.ReasonDownloadFailed, err)
		case err != nil:
			return res, failed(agentconfig.ReasonInternal, err)
		}
		materialized[name] = m
		res.warnings = append(res.warnings, m.Warnings...)
	}
	if agentconfig.HasPolicyErrors(problems) {
		return res, policyRejection(append(problems, res.warnings...))
	}

	// One compile unit per (plugin, policy path) (R21): plugins with different policy_data
	// are checked separately.
	for _, pluginName := range sortedPluginNames(resolved.Plugins) {
		p := resolved.Plugins[pluginName]
		if p == nil || !p.IsEnabled() {
			continue
		}
		if _, skipped := skip[pluginName]; skipped {
			continue
		}
		for _, e := range p.Policies {
			name, ok := agentconfig.InlineBundleName(e)
			if !ok || materialized[name] == nil {
				continue
			}
			m := materialized[name]
			problems = append(problems, inlinepolicy.Check(ctx, inlinepolicy.CheckInput{
				Plugin:        pluginName,
				Bundle:        name,
				PolicyDir:     m.Dir,
				Authored:      m.Authored,
				AuthoredTests: m.AuthoredTests,
				PolicyData:    p.PolicyData,
			})...)
		}
	}
	if agentconfig.HasPolicyErrors(problems) {
		return res, policyRejection(append(problems, res.warnings...))
	}
	res.warnings = append(res.warnings, problems...)
	agentconfig.SortPolicyErrors(res.warnings)

	res.dirs = map[string]string{}
	for _, name := range sortedMaterializedKeys(materialized) {
		m := materialized[name]
		res.dirs[agentconfig.InlineSourcePrefix+name] = m.Dir
		res.reports = append(res.reports, agentconfig.PolicyBundleReport{
			Source:  agentconfig.InlineSourcePrefix + name,
			Digest:  m.Digest,
			Extends: m.Extends,
			Files:   m.Files,
		})
	}
	return res, nil
}

func policyRejection(errs []agentconfig.PolicyError) *applyError {
	agentconfig.SortPolicyErrors(errs)
	var only []agentconfig.PolicyError
	for _, e := range errs {
		if e.Severity == agentconfig.SeverityError {
			only = append(only, e)
		}
	}
	aerr := rejected(agentconfig.ReasonPolicyErrors, inlinepolicy.PolicyErrors(only))
	aerr.PolicyErrors = errs
	return aerr
}

// sourceReports inventories the non-inline policy paths of runtime for the report. OCI trees
// are memoized per (source, dir); local trees are re-read.
func (rc *reconciler) sourceReports(ctx context.Context, runtime *agentConfig) []agentconfig.PolicyBundleReport {
	resolve := rc.boundedResolver()
	if resolve == nil {
		return nil
	}
	sources := map[string]struct{}{}
	for _, p := range runtime.Plugins {
		for _, e := range p.Policies {
			if _, inline := runtime.inlinePolicyDirs[string(e)]; !inline {
				sources[string(e)] = struct{}{}
			}
		}
	}
	var out []agentconfig.PolicyBundleReport
	for _, source := range sortedSetKeys(sources) {
		dir, err := resolve(ctx, source)
		if err != nil {
			continue
		}
		key := source + "\x00" + dir
		if r, ok := rc.inventoryMemo[key]; ok {
			out = append(out, r)
			continue
		}
		digest, files, err := inlinepolicy.Inventory(dir)
		if err != nil {
			continue
		}
		r := agentconfig.PolicyBundleReport{Source: source, Digest: digest, Files: files}
		if agentconfig.KindOf(source) == agentconfig.SourceKindOCI {
			rc.inventoryMemo[key] = r
		}
		out = append(out, r)
	}
	return out
}

// boundedResolver wraps resolvePolicy with prepareNetworkTimeout per call (nil when unset).
func (rc *reconciler) boundedResolver() inlinepolicy.Resolver {
	if rc.resolvePolicy == nil {
		return nil
	}
	return func(ctx context.Context, source string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, prepareNetworkTimeout)
		defer cancel()
		return rc.resolvePolicy(ctx, source)
	}
}

// afterStartup removes the materialized inline bundles startup does not use.
func (rc *reconciler) afterStartup(active *candidate) {
	rc.gcInline(active)
}

// gcInline removes materialized inline bundles that none of keep uses and that are not among
// the newest inlineGCKeepPerBundle per bundle. It runs after startup and after every swap
// (keep = the running, the replaced and the new pending candidate), so a long-running daemon
// does not accumulate one directory per revision.
func (rc *reconciler) gcInline(keep ...*candidate) {
	if !rc.store.Writable() {
		return
	}
	dirs := map[string]struct{}{}
	found := false
	for _, c := range keep {
		if c == nil || c.runtime == nil {
			continue
		}
		found = true
		for _, dir := range c.runtime.inlinePolicyDirs {
			dirs[dir] = struct{}{}
		}
	}
	if !found {
		return
	}
	if err := inlinepolicy.GC(rc.inlineRoot(), dirs, inlineGCKeepPerBundle); err != nil {
		rc.logger.Warn("Could not clean up old inline policy bundles", "error", err)
	}
}

func sortedBoolKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedMaterializedKeys(m map[string]*inlinepolicy.Materialized) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedPluginNames(m map[string]*agentconfig.Plugin) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
