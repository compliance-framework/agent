package cmd

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/agent/internal/policyview"
	"github.com/compliance-framework/api/pkg/agentconfig"
)

// Path shadowing (R83). Plugins seed evidence UUIDs from the policy path string they
// receive, so an inline bundle that extends a source is given to plugins at the source's own
// path, and each such plugin runs in a view (internal/policyview) where that path resolves to
// the bundle's tree: inherited and overridden modules keep the vendor's streams with any
// plugin build.
//
// A bundle is shadowed when its extends source's plugin path is shadowable (relative, ending
// in policies/: every OCI source) and every enabled plugin that uses it can be given a view:
// it does not also load the source or another bundle on the same path, and its other
// relative paths still resolve in the view. Otherwise plugins receive the bundle at its own
// path under inlineLinksDir and its modules start path-based streams (R88;
// unshadowedWarnings says so per plugin).

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
	unavailable := ""
	switch {
	case resolve == nil:
		unavailable = "no policy resolver"
	case rc.store == nil || !rc.store.Writable():
		unavailable = "plugin views need a writable state directory"
	case !inlinepolicy.SymlinksSupported(rc.viewsRoot()):
		unavailable = "plugin views need symlinks, which the file system does not support"
	}
	if unavailable != "" {
		for name := range refs {
			if b := resolved.PolicyBundles[name]; b != nil && b.Extends != nil {
				plan.reasons[name] = unavailable
			}
		}
		return plan
	}
	extendsPath := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(refs)) {
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

	for _, pluginName := range slices.Sorted(maps.Keys(resolved.Plugins)) {
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
		for _, pluginName := range slices.Sorted(maps.Keys(plan.plugins)) {
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
	for _, name := range slices.Sorted(maps.Keys(plan.reasons)) {
		if rc.logOnce("shadow\x00" + name + "\x00" + plan.reasons[name]) {
			rc.logger.Info("Inline bundle is not shadowed; plugins receive it at its own path, so its modules start new evidence streams", "bundle", name, "reason", plan.reasons[name])
		}
	}
	return plan
}

// unshadowedWarnings warns, once per enabled plugin and inline bundle it uses, about an
// extends bundle that is not shadowed (R88): the plugin receives it at its own path, so the
// modules that would keep the vendor's evidence streams at the source's path
// (inlinepolicy.UnshadowedForks) start new ones. The reason is planShadowing's.
func unshadowedWarnings(resolved agentconfig.Config, skip map[string]string, plan shadowPlan, materialized map[string]*inlinepolicy.Materialized) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	for _, pluginName := range slices.Sorted(maps.Keys(resolved.Plugins)) {
		p := resolved.Plugins[pluginName]
		if p == nil || !p.IsEnabled() {
			continue
		}
		if _, skipped := skip[pluginName]; skipped {
			continue
		}
		seen := map[string]bool{}
		for _, e := range p.Policies {
			name, ok := agentconfig.InlineBundleName(e)
			if !ok || seen[name] || materialized[name] == nil {
				continue
			}
			seen[name] = true
			m := materialized[name]
			forks := inlinepolicy.UnshadowedForks(m)
			if len(forks) == 0 {
				continue
			}
			why := plan.reasons[name]
			if why == "" {
				why = fmt.Sprintf("%s cannot be shadowed", m.ExtendsDir)
			}
			listed := forks
			if len(listed) > 10 {
				listed = append(slices.Clip(listed[:10]), fmt.Sprintf("and %d more", len(forks)-10))
			}
			out = append(out, agentconfig.PolicyError{Bundle: name, Severity: agentconfig.SeverityWarning, Code: inlinepolicy.CodePolicyStreamForked,
				Message: fmt.Sprintf("plugin %s receives bundle %s at %s, not at the path of %s (%s), so %d of its modules (%s) record their evidence in new streams instead of the vendor's",
					pluginName, name, m.Path, m.Extends.Source, why, len(forks), strings.Join(listed, ", "))})
		}
	}
	return out
}

// fallbackInlinePath is the path plugins receive for an inline bundle that is not shadowed,
// or "" (an absolute tree directory, unaffected by views) without symlinks.
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
	for _, pluginName := range slices.Sorted(maps.Keys(plan.plugins)) {
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
