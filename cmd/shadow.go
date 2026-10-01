package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/agent/internal/policyview"
	"github.com/compliance-framework/api/pkg/agentconfig"
)

// Path shadowing (prototype). A plugin keeps an evidence stream exactly when it receives the
// same policy path string (policy-manager seeds evidence UUIDs from it). So an inline bundle
// that extends a source is given to plugins at the source's own plugin path, and the plugin
// runs in a per-plugin view (internal/policyview) in which that path resolves to the
// bundle's tree. Inherited and overridden modules then keep the vendor streams with any
// plugin build, and no continuity policy_id is needed (R82's injection remains the fallback).
//
// A bundle is shadowed when its extends source's plugin path is shadowable (relative, ending
// in policies/: every OCI source) and every enabled plugin that uses it can be given a view:
// the plugin does not also load the source itself or another bundle shadowing the same path,
// and every other relative path it receives can still be resolved in the view. Otherwise the
// bundle falls back to R82 (relative inline path plus continuity policy_id), and loading it
// next to its source is reported by the R75 identity checks as before.

// shadowPlan is what prepareInline decided about shadowing, with the policy paths each
// plugin receives for its non-inline entries (resolved once, reused for the views).
type shadowPlan struct {
	shadow map[string]bool // bundle name -> shadowed
	// plugins are the enabled, not skipped plugins that use an inline bundle.
	plugins map[string]shadowPlugin
	// reasons say why a candidate bundle was not shadowed (logged once).
	reasons map[string]string
}

type shadowPlugin struct {
	bundles []string // inline bundles it uses, in order, deduplicated
	others  []string // the paths it receives for every non-inline entry
	sources map[string]bool
}

// viewsRoot is where the plugin views live, under the state directory.
func (rc *reconciler) viewsRoot() string {
	return filepath.Join(rc.store.Dir(), "views")
}

// planShadowing decides which of the bundles in refs are shadowed.
func (rc *reconciler) planShadowing(ctx context.Context, resolved agentconfig.Config, skip map[string]string, refs map[string]bool) shadowPlan {
	plan := shadowPlan{shadow: map[string]bool{}, plugins: map[string]shadowPlugin{}, reasons: map[string]string{}}
	resolve := rc.boundedResolver()
	if resolve == nil || rc.store == nil || !rc.store.Writable() || !inlinepolicy.SymlinksSupported(rc.viewsRoot()) {
		return plan
	}
	extendsPath := map[string]string{}
	for _, name := range sortedBoolKeys(refs) {
		b := resolved.PolicyBundles[name]
		if b == nil || b.Extends == nil {
			continue
		}
		dir, err := resolve(ctx, *b.Extends)
		if err != nil {
			continue // Materialize reports it
		}
		if err := policyview.Shadowable(dir); err != nil {
			plan.reasons[name] = err.Error()
			continue
		}
		extendsPath[name] = dir
		plan.shadow[name] = true
	}

	for _, pluginName := range sortedPluginNames(resolved.Plugins) {
		p := resolved.Plugins[pluginName]
		if p == nil || !p.IsEnabled() {
			continue
		}
		if _, skipped := skip[pluginName]; skipped {
			continue
		}
		sp := shadowPlugin{sources: map[string]bool{}}
		seen := map[string]bool{}
		for _, e := range p.Policies {
			entry := string(e)
			if seen[entry] {
				continue
			}
			seen[entry] = true
			if name, ok := agentconfig.InlineBundleName(e); ok {
				sp.bundles = append(sp.bundles, name)
				continue
			}
			dir, err := resolve(ctx, entry)
			if err != nil {
				continue // prefetch reports it
			}
			sp.others = append(sp.others, dir)
			sp.sources[filepath.Clean(dir)] = true
		}
		if len(sp.bundles) > 0 {
			plan.plugins[pluginName] = sp
		}
	}
	if len(plan.shadow) == 0 {
		return plan
	}

	// Drop candidates until every plugin can be given a view.
	drop := func(name, why string) bool {
		if !plan.shadow[name] {
			return false
		}
		delete(plan.shadow, name)
		plan.reasons[name] = why
		return true
	}
	for changed := true; changed; {
		changed = false
		for _, pluginName := range sortedMapKeys(plan.plugins) {
			sp := plan.plugins[pluginName]
			var shadowed, others []string
			byPath := map[string][]string{}
			for _, name := range sp.bundles {
				if !plan.shadow[name] {
					others = appendPath(others, rc.fallbackInlinePath(name))
					continue
				}
				path := extendsPath[name]
				if sp.sources[filepath.Clean(path)] {
					changed = drop(name, fmt.Sprintf("plugin %s also loads %s (%s) itself", pluginName, *resolved.PolicyBundles[name].Extends, path)) || changed
					others = appendPath(others, rc.fallbackInlinePath(name))
					continue
				}
				byPath[filepath.Clean(path)] = append(byPath[filepath.Clean(path)], name)
				shadowed = append(shadowed, path)
			}
			for _, names := range byPath {
				if len(names) > 1 {
					for _, name := range names {
						changed = drop(name, fmt.Sprintf("plugin %s uses more than one bundle that extends %s", pluginName, extendsPath[name])) || changed
					}
				}
			}
			if changed {
				break // recompute with the new decisions
			}
			if _, err := policyview.Plan(shadowed, append(others, sp.others...)); err != nil {
				for _, name := range sp.bundles {
					changed = drop(name, fmt.Sprintf("plugin %s cannot be given a view: %v", pluginName, err)) || changed
				}
				if changed {
					break
				}
			}
		}
	}
	for _, name := range sortedMapKeys(plan.reasons) {
		if rc.logOnce("shadow\x00" + name + "\x00" + plan.reasons[name]) {
			rc.logger.Info("Inline bundle is not shadowed; plugins receive it at its own path, with continuity policy_ids", "bundle", name, "reason", plan.reasons[name])
		}
	}
	return plan
}

// fallbackInlinePath is the path plugins receive for an inline bundle that is not shadowed
// (R82), or "" (an absolute tree directory, unaffected by views) without symlinks.
func (rc *reconciler) fallbackInlinePath(name string) string {
	l := rc.inlineLayout()
	if !inlinepolicy.SymlinksSupported(l.Links) {
		return ""
	}
	return filepath.Join(l.Links, name, policyview.TreeDir)
}

func appendPath(paths []string, p string) []string {
	if p == "" {
		return paths
	}
	return append(paths, p)
}

// buildViews returns the view of every plugin that receives a shadowed bundle.
func (rc *reconciler) buildViews(plan shadowPlan, materialized map[string]*inlinepolicy.Materialized) (map[string]*policyview.View, error) {
	var views map[string]*policyview.View
	base, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(rc.viewsRoot())
	if err != nil {
		return nil, err
	}
	for _, pluginName := range sortedMapKeys(plan.plugins) {
		sp := plan.plugins[pluginName]
		var shadowed, others []string
		targets := map[string]string{} // plugin path -> the directory holding the tree
		for _, name := range sp.bundles {
			m := materialized[name]
			if m == nil {
				continue
			}
			if !m.Shadowed {
				others = append(others, m.Path)
				continue
			}
			dir, err := filepath.Abs(filepath.Dir(m.Dir))
			if err != nil {
				return nil, err
			}
			shadowed = append(shadowed, m.Path)
			targets[m.Path] = dir
		}
		if len(shadowed) == 0 {
			continue
		}
		links, err := policyview.Plan(shadowed, append(others, sp.others...))
		if err != nil {
			// planShadowing checked the same paths.
			return nil, fmt.Errorf("plugin %s: %w", pluginName, err)
		}
		viewLinks := map[string]string{}
		for path, link := range links {
			viewLinks[link] = targets[path]
		}
		if views == nil {
			views = map[string]*policyview.View{}
		}
		views[pluginName] = &policyview.View{
			Dir:   policyview.DirFor(root, pluginName, base, viewLinks),
			Base:  base,
			Links: viewLinks,
			// Plugin-owned entries in the view (rule 1) are warnings, once per view and name.
			Warn: rc.logger.Warn,
		}
	}
	return views, nil
}
