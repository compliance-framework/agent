package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/api/pkg/agentconfig"
)

// Evidence identity across a plugin's policy paths (R66, R75). A plugin evaluates each of
// its policy paths separately and records evidence for every policy module of each, so a
// policy loaded twice is reported twice:
//
//   - duplicate-policy-id: two modules declare the same policy_id;
//   - duplicate-policy-identity: two modules from different policy paths have the same
//     evidence identity: the same seed (a policy_id that continues the stream of a module
//     loaded too), or, without policy_id, the same package and bundle-relative file (an
//     inline bundle listed next to the source it extends);
//   - duplicate-policy-package (R66): the same package from two policy paths otherwise.
//
// The first two are errors when the overlay introduces them (it changes the plugin's
// policies or one of the inline bundles involved) and warnings when they come from the
// config file (R34). The last is always a warning. Plugins that use no inline bundle are not
// checked: their policy paths are the file's and the vendors' business.

// codeDuplicatePolicyPackage is the PolicyError code of R66.
const codeDuplicatePolicyPackage = "duplicate-policy-package"

// loadedModule is one policy module a plugin loads.
type loadedModule struct {
	entry      string // the plugin's policy entry
	bundle     string // the inline bundle's name, "" for other sources
	pluginPath string // the path the agent passes the plugin for entry
	id         inlinepolicy.ModuleIdentity
	authored   bool
	// seedFile and seedPath are the module's evidence seed (policy_file, _policy_path).
	seedFile, seedPath string
}

func newLoadedModule(entry, bundle, pluginPath string, id inlinepolicy.ModuleIdentity, authored bool) loadedModule {
	m := loadedModule{entry: entry, bundle: bundle, pluginPath: pluginPath, id: id, authored: authored}
	m.seedFile, m.seedPath = inlinepolicy.SeedOf(id, pluginPath)
	return m
}

func (m loadedModule) where() string {
	return fmt.Sprintf("%s in %s", m.id.Path, m.entry)
}

// policyIdentities returns the R66/R75 problems of every enabled plugin that uses an inline
// bundle. touched are the pointers the overlay changed. A source that cannot be resolved
// here is skipped (prefetch reports it).
func (rc *reconciler) policyIdentities(ctx context.Context, resolved agentconfig.Config, skip map[string]string, materialized map[string]*inlinepolicy.Materialized, touched []string) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	for _, pluginName := range sortedPluginNames(resolved.Plugins) {
		p := resolved.Plugins[pluginName]
		if p == nil || !p.IsEnabled() {
			continue
		}
		if _, skipped := skip[pluginName]; skipped {
			continue
		}
		var modules []loadedModule
		usesInline := false
		seenEntry := map[string]bool{}
		for _, e := range p.Policies {
			entry := string(e)
			if seenEntry[entry] {
				continue
			}
			seenEntry[entry] = true
			if name, ok := agentconfig.InlineBundleName(e); ok {
				m := materialized[name]
				if m == nil {
					continue
				}
				usesInline = true
				for _, id := range m.Identities {
					modules = append(modules, newLoadedModule(entry, name, m.Path, id, m.Authored[id.Path]))
				}
				continue
			}
			dir, ids, err := rc.sourceIdentities(ctx, entry)
			if err != nil {
				continue
			}
			for _, id := range ids {
				modules = append(modules, newLoadedModule(entry, "", dir, id, false))
			}
		}
		if !usesInline {
			continue
		}
		pluginTouched := touchedByOverlay(agentconfig.Pointer("plugins", pluginName, "policies"), touched)
		severity := func(a, b loadedModule) string {
			for _, m := range []loadedModule{a, b} {
				if pluginTouched || (m.bundle != "" && touchedByOverlay(agentconfig.Pointer("policy_bundles", m.bundle), touched)) {
					return agentconfig.SeverityError
				}
			}
			return agentconfig.SeverityWarning
		}
		out = append(out, identityProblems(pluginName, modules, severity)...)
	}
	return out
}

// identityProblems compares every pair of modules of one plugin.
func identityProblems(pluginName string, modules []loadedModule, severity func(a, b loadedModule) string) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	identityPackages := map[string]bool{} // packages with an identity problem across paths
	samePackage := map[string][]loadedModule{}
	report := func(a, b loadedModule, sev, code, msg string) {
		at := b
		if at.bundle == "" || (a.bundle != "" && a.authored && !b.authored) {
			at = a
		}
		out = append(out, agentconfig.PolicyError{Bundle: at.bundle, Path: at.id.Path, Severity: sev, Code: code,
			Message: fmt.Sprintf("plugin %s: %s", pluginName, msg)})
	}
	for j, b := range modules {
		for _, a := range modules[:j] {
			sameEntry := a.entry == b.entry
			switch {
			case a.id.PolicyID != "" && a.id.PolicyID == b.id.PolicyID:
				// Within one source, two vendor modules are the vendor's business, and two
				// authored ones are the API's contract check (CheckContract).
				if sameEntry && a.authored == b.authored {
					continue
				}
				if !sameEntry {
					identityPackages[a.id.Package], identityPackages[b.id.Package] = true, true
				}
				report(a, b, severity(a, b), agentconfig.PolicyCodeDuplicatePolicyID,
					fmt.Sprintf("policy_id %q is declared by both %s and %s, so their evidence shares one stream; give each policy its own policy_id", a.id.PolicyID, a.where(), b.where()))
			case sameEntry:
				continue
			case a.id.Package == b.id.Package && sameSeed(a, b):
				identityPackages[a.id.Package] = true
				report(a, b, severity(a, b), agentconfig.PolicyCodeDuplicatePolicyIdentity,
					fmt.Sprintf("%s and %s write to the same evidence stream (package %s), so each evidence is recorded twice; load only one of them: if one is an inline bundle that extends the other, replace the source with the bundle instead of listing both", a.where(), b.where(), a.id.Package))
			case a.id.Package == b.id.Package && a.id.PolicyID == "" && b.id.PolicyID == "" && a.id.Path == b.id.Path:
				identityPackages[a.id.Package] = true
				report(a, b, severity(a, b), agentconfig.PolicyCodeDuplicatePolicyIdentity,
					fmt.Sprintf("%s is loaded from both %s and %s (package %s), so the plugin records its evidence twice, in two streams; load only one of them: if one is an inline bundle that extends the other, replace the source with the bundle instead of listing both", a.id.Path, a.entry, b.entry, a.id.Package))
			case a.id.Package == b.id.Package:
				samePackage[a.id.Package] = append(samePackage[a.id.Package], a, b)
			}
		}
	}
	for _, pkg := range sortedMapKeys(samePackage) {
		if identityPackages[pkg] {
			continue
		}
		var at loadedModule
		var entries []string
		seen := map[string]bool{}
		for _, m := range samePackage[pkg] {
			if !seen[m.entry] {
				seen[m.entry] = true
				entries = append(entries, m.entry)
			}
			if at.bundle == "" && m.bundle != "" {
				at = m
			}
		}
		if at.entry == "" {
			at = samePackage[pkg][0]
		}
		out = append(out, agentconfig.PolicyError{
			Bundle:   at.bundle,
			Path:     at.id.Path,
			Severity: agentconfig.SeverityWarning,
			Code:     codeDuplicatePolicyPackage,
			Message: fmt.Sprintf("plugin %s: package %s is defined in more than one of its policy paths (%s), so the plugin records its evidence more than once; if one is an inline bundle that extends the other, replace the source with the bundle instead of listing both",
				pluginName, pkg, strings.Join(entries, ", ")),
		})
	}
	return out
}

func sameSeed(a, b loadedModule) bool {
	return a.seedFile == b.seedFile && a.seedPath == b.seedPath
}

// sourceIdentities resolves an OCI or local policy source and returns the path plugins
// receive for it and its modules' identities. OCI trees are memoized per (source, dir).
func (rc *reconciler) sourceIdentities(ctx context.Context, source string) (string, []inlinepolicy.ModuleIdentity, error) {
	dir, _, err := rc.sourceInventory(ctx, source)
	if err != nil {
		return "", nil, err
	}
	key := source + "\x00" + dir
	if ids, ok := rc.identityMemo[key]; ok {
		return dir, ids, nil
	}
	ids, err := inlinepolicy.TreeIdentities(dir)
	if err != nil {
		return "", nil, err
	}
	if agentconfig.KindOf(source) == agentconfig.SourceKindOCI {
		if len(rc.identityMemo) >= artifactMemoLimit {
			rc.identityMemo = map[string][]inlinepolicy.ModuleIdentity{}
		}
		rc.identityMemo[key] = ids
	}
	return dir, ids, nil
}
