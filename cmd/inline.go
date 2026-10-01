package cmd

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/agent/internal/policyview"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/agentconfig/regocheck"
)

// inlineGCKeepPerBundle is how many materialized versions of each bundle GC keeps besides the
// active ones.
const inlineGCKeepPerBundle = 5

// inlineLinksDir is where the stable links of inline bundles live, relative to the agent's
// working directory like the OCI policy cache next to it, so plugins receive a bundle that
// is not shadowed as .compliance-framework/policies/_inline/<name>/policies. The leading
// underscore keeps it apart from the OCI cache: OCI repository path components start with
// [a-z0-9], so no image extracts to _inline.
var inlineLinksDir = filepath.Join(AgentPolicyDir, "_inline")

// inlineLayout is where inline bundles are materialized (under the state dir, R31) and
// where plugins receive them when they are not shadowed.
func (rc *reconciler) inlineLayout() inlinepolicy.Layout {
	links := rc.inlineLinks
	if links == "" {
		links = inlineLinksDir
	}
	return inlinepolicy.Layout{Store: filepath.Join(rc.store.Dir(), "inline"), Links: links}
}

// prepareInline is prepare step 8 (G3b): the parse-level checks on every bundle, then
// materialize each bundle an enabled plugin references and check it per (plugin, path) the
// way the plugin will load it. Any error rejects the revision (policy-errors); warnings are
// kept for the report. No network is touched before the Classify gate: extends trees are
// fetched here, after it.
func (rc *reconciler) prepareInline(ctx context.Context, resolved agentconfig.Config, skip map[string]string, origin policyOrigin) (inlineResult, *applyError) {
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

	// Path shadowing is decided before materializing: it sets the path plugins receive.
	plan := rc.planShadowing(ctx, resolved, skip, refs)

	materialized := map[string]*inlinepolicy.Materialized{}
	var problems []agentconfig.PolicyError
	for _, name := range slices.Sorted(maps.Keys(refs)) {
		m, err := inlinepolicy.Materialize(ctx, rc.inlineLayout(), name, resolved.PolicyBundles[name], rc.boundedResolver(),
			inlinepolicy.Options{Shadow: plan.shadow[name]})
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
	for _, pluginName := range slices.Sorted(maps.Keys(resolved.Plugins)) {
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
	for _, name := range slices.Sorted(maps.Keys(materialized)) {
		problems = append(problems, inlinepolicy.OverrideStreams(materialized[name])...)
	}
	problems = append(problems, rc.policyIdentities(ctx, resolved, skip, materialized, origin)...)
	if agentconfig.HasPolicyErrors(problems) {
		return res, policyRejection(append(problems, res.warnings...))
	}
	res.warnings = append(res.warnings, problems...)
	res.warnings = dedupePolicyErrors(res.warnings)
	agentconfig.SortPolicyErrors(res.warnings)

	views, err := rc.buildViews(plan, materialized)
	if err != nil {
		return res, failed(agentconfig.ReasonInternal, err)
	}
	res.views = views

	res.materialized = materialized
	res.dirs = map[string]string{}
	res.trees = map[string]string{}
	res.digests = map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(materialized)) {
		m := materialized[name]
		entry := agentconfig.InlineSourcePrefix + name
		res.dirs[entry] = m.Path
		res.trees[entry] = m.Dir
		res.digests[entry] = m.Digest
		res.reports = append(res.reports, agentconfig.PolicyBundleReport{
			Source:  entry,
			Digest:  m.Digest,
			Extends: m.Extends,
			Files:   m.Files,
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
	for _, source := range slices.Sorted(maps.Keys(sources)) {
		dir, r, err := rc.sourceInventory(ctx, source)
		if err != nil {
			continue
		}
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
// starting or fallback candidate, nor a bundle's stable link uses, and that are not among
// the newest inlineGCKeepPerBundle per bundle, and the plugin views no such candidate uses.
// It runs after startup and right after every swap, so a long-running daemon does not
// accumulate one directory per revision; the configuration still draining after a swap is
// the running candidate, so its trees and views are kept. It holds inlineMu, so it never
// races activateInline.
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
	views := map[string]struct{}{}
	found := false
	for _, c := range keep {
		if c == nil || c.runtime == nil {
			continue
		}
		found = true
		for _, dir := range c.runtime.inlineTrees {
			dirs[dir] = struct{}{}
		}
		for _, v := range c.runtime.pluginViews {
			views[v.Dir] = struct{}{}
		}
	}
	if !found {
		return
	}
	if err := inlinepolicy.GC(rc.inlineLayout(), dirs, inlineGCKeepPerBundle); err != nil {
		rc.logger.Warn("Could not clean up old inline policy bundles", "error", err)
	}
	if root, err := filepath.Abs(rc.viewsRoot()); err == nil {
		if err := policyview.GC(root, views); err != nil {
			rc.logger.Warn("Could not clean up old plugin views", "error", err)
		}
	}
}

// activateInline points the stable path of each inline bundle c uses at c's tree (R67),
// then creates the views of the plugins that receive a shadowed bundle. A view that cannot
// be created is only logged: pluginWorkDir ensures it again before each run of its plugin
// and fails just that run, so one plugin's view never stops the configuration (views are
// content-addressed and survive restarts, so failing here could crash-loop the agent).
func (rc *reconciler) activateInline(c *candidate) error {
	if c == nil || c.runtime == nil || len(c.runtime.inlineTrees) == 0 {
		return nil
	}
	rc.inlineMu.Lock()
	defer rc.inlineMu.Unlock()
	var errs []error
	for _, entry := range slices.Sorted(maps.Keys(c.runtime.inlineTrees)) {
		name := strings.TrimPrefix(entry, agentconfig.InlineSourcePrefix)
		errs = append(errs, inlinepolicy.Activate(rc.inlineLayout(), name, c.runtime.inlineTrees[entry]))
	}
	for _, plugin := range slices.Sorted(maps.Keys(c.runtime.pluginViews)) {
		view := c.runtime.pluginViews[plugin]
		if err := view.Ensure(); err != nil {
			rc.logger.Warn("Could not prepare a plugin's view; its runs fail until it is fixed", "plugin", plugin, "view", view.Dir, "error", err)
		}
	}
	return errors.Join(errs...)
}
