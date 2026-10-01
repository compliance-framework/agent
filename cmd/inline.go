package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"

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
func (rc *reconciler) prepareInline(ctx context.Context, resolved agentconfig.Config, skip map[string]string, touched []string) (inlineResult, *applyError) {
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
	for _, name := range sortedMaterializedKeys(materialized) {
		problems = append(problems, inlinepolicy.OverrideStreams(materialized[name])...)
	}
	problems = append(problems, rc.policyIdentities(ctx, resolved, skip, materialized, touched)...)
	if agentconfig.HasPolicyErrors(problems) {
		return res, policyRejection(append(problems, res.warnings...))
	}
	res.warnings = append(res.warnings, problems...)
	res.warnings = dedupePolicyErrors(res.warnings)
	agentconfig.SortPolicyErrors(res.warnings)

	res.materialized = materialized
	res.dirs = map[string]string{}
	res.trees = map[string]string{}
	res.digests = map[string]string{}
	for _, name := range sortedMaterializedKeys(materialized) {
		m := materialized[name]
		entry := agentconfig.InlineSourcePrefix + name
		res.dirs[entry] = m.Path
		res.trees[entry] = m.Dir
		res.digests[entry] = m.Digest
		res.reports = append(res.reports, agentconfig.PolicyBundleReport{
			Source:     entry,
			Digest:     m.Digest,
			Extends:    m.Extends,
			Files:      m.Files,
			PluginPath: m.Path,
		})
		res.artifacts = append(res.artifacts, artifactTree{digest: m.Digest, dir: m.Dir})
		if m.Extends != nil {
			res.artifacts = append(res.artifacts, artifactTree{digest: m.Extends.Digest, dir: m.ExtendsDir})
		}
	}
	return res, nil
}

// dedupePolicyErrors drops exact duplicates (the per-plugin checks of one bundle repeat
// plugin-independent findings) and a warning superseded by an error with the same bundle,
// path and code (the API's static check may only warn about what the agent, which sees the
// whole tree, rejects).
func dedupePolicyErrors(errs []agentconfig.PolicyError) []agentconfig.PolicyError {
	type site struct{ bundle, path, code string }
	isError := map[site]bool{}
	for _, e := range errs {
		if e.Code != "" && e.Severity == agentconfig.SeverityError {
			isError[site{e.Bundle, e.Path, e.Code}] = true
		}
	}
	seen := map[agentconfig.PolicyError]bool{}
	out := make([]agentconfig.PolicyError, 0, len(errs))
	for _, e := range errs {
		if seen[e] || (e.Severity == agentconfig.SeverityWarning && e.Code != "" && isError[site{e.Bundle, e.Path, e.Code}]) {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

func policyRejection(errs []agentconfig.PolicyError) *applyError {
	errs = dedupePolicyErrors(errs)
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

// sourceReports inventories the non-inline policy paths of runtime for the report, with the
// trees to upload as artifacts.
func (rc *reconciler) sourceReports(ctx context.Context, runtime *agentConfig) ([]agentconfig.PolicyBundleReport, []artifactTree) {
	sources := map[string]struct{}{}
	for _, p := range runtime.Plugins {
		for _, e := range p.Policies {
			if _, inline := runtime.inlinePolicyDirs[string(e)]; !inline {
				sources[string(e)] = struct{}{}
			}
		}
	}
	var reports []agentconfig.PolicyBundleReport
	var trees []artifactTree
	for _, source := range sortedSetKeys(sources) {
		dir, r, err := rc.sourceInventory(ctx, source)
		if err != nil {
			continue
		}
		// The resolver returns the exact path string plugins receive for the source (R77).
		r.PluginPath = dir
		reports = append(reports, r)
		trees = append(trees, artifactTree{digest: r.Digest, dir: dir})
	}
	return reports, trees
}

// sourceInventory resolves an OCI or local policy source and inventories its tree. OCI trees
// are memoized per (source, dir); local trees are re-read.
func (rc *reconciler) sourceInventory(ctx context.Context, source string) (string, agentconfig.PolicyBundleReport, error) {
	resolve := rc.boundedResolver()
	if resolve == nil {
		return "", agentconfig.PolicyBundleReport{}, errors.New("no policy resolver")
	}
	dir, err := resolve(ctx, source)
	if err != nil {
		return "", agentconfig.PolicyBundleReport{}, err
	}
	key := source + "\x00" + dir
	if r, ok := rc.inventoryMemo[key]; ok {
		return dir, r, nil
	}
	digest, files, err := inlinepolicy.Inventory(dir)
	if err != nil {
		return "", agentconfig.PolicyBundleReport{}, err
	}
	r := agentconfig.PolicyBundleReport{Source: source, Digest: digest, Files: files}
	if agentconfig.KindOf(source) == agentconfig.SourceKindOCI {
		rc.inventoryMemo[key] = r
	}
	return dir, r, nil
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

// gcInline removes materialized inline bundles that none of keep, the running, pending,
// starting or fallback candidate, nor a bundle's current symlink uses, and that are not among
// the newest inlineGCKeepPerBundle per bundle. It runs after startup and after every swap,
// so a long-running daemon does not accumulate one directory per revision. It holds
// inlineMu, so it never races activateInline.
func (rc *reconciler) gcInline(keep ...*candidate) {
	if !rc.store.Writable() {
		return
	}
	rc.mu.Lock()
	keep = append(keep, rc.active, rc.pending, rc.starting, rc.fallback)
	rc.mu.Unlock()

	rc.inlineMu.Lock()
	defer rc.inlineMu.Unlock()
	dirs := map[string]struct{}{}
	found := false
	for _, c := range keep {
		if c == nil || c.runtime == nil {
			continue
		}
		found = true
		for _, dir := range c.runtime.inlineTrees {
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

// activateInline points the stable path of each inline bundle c uses at c's tree (R67).
func (rc *reconciler) activateInline(c *candidate) error {
	if c == nil || c.runtime == nil || len(c.runtime.inlineTrees) == 0 {
		return nil
	}
	rc.inlineMu.Lock()
	defer rc.inlineMu.Unlock()
	var errs []error
	for _, entry := range sortedStringKeys(c.runtime.inlineTrees) {
		name := strings.TrimPrefix(entry, agentconfig.InlineSourcePrefix)
		errs = append(errs, inlinepolicy.Activate(rc.inlineRoot(), name, c.runtime.inlineTrees[entry]))
	}
	return errors.Join(errs...)
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

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
