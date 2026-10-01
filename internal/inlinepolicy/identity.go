package inlinepolicy

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/open-policy-agent/opa/v1/ast"
)

// Evidence identity (R74, R75). A plugin seeds each evidence UUID with the policy's package,
// its file (the path the agent passed the plugin joined with the module's path in the
// bundle) and, through its labels, that path; a policy_id replaces the location
// (policyeval.SeedPath). The agent reads policy_id statically, as the API's contract check
// does: only `policy_id := "<literal>"` declared once per package counts, which is the only
// form CheckContract accepts.

// ModuleIdentity is what decides the evidence stream of one policy module.
type ModuleIdentity struct {
	Path     string // slash-separated, relative to the policy root
	Package  string // without "data."
	PolicyID string // the package's policy_id, "" when it declares none (or not validly)
}

// Site is where an authored construct is.
type Site struct {
	Path     string
	Row, Col int
}

// Identities returns the identity of every non-test module of a compliance_framework
// package in files, sorted by path. Modules that do not parse are skipped: the checks report
// them.
func Identities(files map[string][]byte) []ModuleIdentity {
	modules := parseModules(files)
	ids := policyeval.StaticPolicyIDs(modules)
	var out []ModuleIdentity
	for _, p := range slices.Sorted(maps.Keys(modules)) {
		pkg := packageOf(modules[p])
		if policyeval.IsTestFile(p) || !policyeval.IsPolicyPackage(pkg) {
			continue
		}
		out = append(out, ModuleIdentity{Path: p, Package: pkg, PolicyID: ids[pkg]})
	}
	return out
}

// TreeIdentities reads the policy tree at dir and returns Identities of it.
func TreeIdentities(dir string) ([]ModuleIdentity, error) {
	files, _, err := readTree(dir)
	if err != nil {
		return nil, err
	}
	return Identities(files), nil
}

// authoredSites returns the authored non-test modules of files that define violation as a
// set (`violation contains ...`, R76) and that declare a policy_id rule.
func authoredSites(files map[string][]byte, authored map[string]bool) (setViolations, policyIDRules []Site) {
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if !authored[p] || !strings.HasSuffix(p, ".rego") || policyeval.IsTestFile(p) {
			continue
		}
		mod := parseRego(p, files[p])
		if mod == nil || !policyeval.IsPolicyPackage(packageOf(mod)) {
			continue
		}
		var setSite, idSite *Site
		for _, rule := range mod.Rules {
			loc := rule.Head.Location
			if loc == nil {
				loc = rule.Location
			}
			site := Site{Path: p}
			if loc != nil {
				site.Row, site.Col = loc.Row, loc.Col
			}
			switch policyeval.RuleName(rule) {
			case "violation":
				if setSite == nil && rule.Head.Key != nil && rule.Head.Value == nil {
					setSite = &site
				}
			case "policy_id":
				if idSite == nil {
					idSite = &site
				}
			}
		}
		if setSite != nil {
			setViolations = append(setViolations, *setSite)
		}
		if idSite != nil {
			policyIDRules = append(policyIDRules, *idSite)
		}
	}
	return setViolations, policyIDRules
}

// SeedOf returns the evidence seed values (policy_file, _policy_path) of module id when a
// plugin loads it from pluginPath, as policy-manager computes them: OPA gives plugins the
// policy file as the path joined with the module's path (cleaned), and policyeval.SeedPath
// applies the policy_id.
func SeedOf(id ModuleIdentity, pluginPath string) (string, string) {
	file := filepath.Join(pluginPath, filepath.FromSlash(id.Path))
	return policyeval.SeedPath(id.PolicyID, file, pluginPath)
}

// OverrideStreams warns about the modules of an extends bundle that do not keep the evidence
// stream of the vendor module at the same path (R75), comparing what plugins seed with: the
// vendor module loaded from the extends source and the module loaded from the bundle's path.
// An override that changes the package is policy-package-changed; any other override, and
// the inherited modules of a bundle plugins receive at its own path (not shadowed), are
// policy-stream-forked. A shadowed bundle keeps every stream its modules keep the package
// of.
func OverrideStreams(m *Materialized) []agentconfig.PolicyError {
	if m == nil || m.Extends == nil {
		return nil
	}
	vendor := map[string]ModuleIdentity{}
	for _, id := range m.ExtendsIdentities {
		vendor[id.Path] = id
	}
	var out []agentconfig.PolicyError
	warn := func(p, code, format string, args ...any) {
		out = append(out, agentconfig.PolicyError{Bundle: m.Name, Path: p, Severity: agentconfig.SeverityWarning, Code: code, Message: fmt.Sprintf(format, args...)})
	}
	var inherited []string
	for _, id := range m.Identities {
		v, replaced := vendor[id.Path]
		if !replaced {
			continue
		}
		if m.Authored[id.Path] && id.Package != v.Package {
			warn(id.Path, agentconfig.PolicyCodePolicyPackageChanged,
				"the override of %s changes its package from %s to %s, which starts a new evidence stream for it; keep `package %s` to continue the vendor policy's stream",
				id.Path, v.Package, id.Package, v.Package)
			continue
		}
		vendorFile, vendorPath := SeedOf(v, m.ExtendsDir)
		file, policyPath := SeedOf(id, m.Path)
		if file == vendorFile && policyPath == vendorPath {
			continue
		}
		if !m.Authored[id.Path] {
			inherited = append(inherited, id.Path)
			continue
		}
		got := "no policy_id"
		if id.PolicyID != "" {
			got = fmt.Sprintf("policy_id %q", id.PolicyID)
		}
		hint := ""
		if v.PolicyID != "" {
			hint = fmt.Sprintf("; declare `policy_id := %q` to continue the vendor policy's stream", v.PolicyID)
		}
		warn(id.Path, CodePolicyStreamForked,
			"the override of %s has %s, so plugins that load this bundle instead of %s record its evidence in a new stream%s",
			id.Path, got, m.Extends.Source, hint)
	}
	if len(inherited) > 0 {
		warn("", CodePolicyStreamForked,
			"bundle %s is not shadowed, so plugins receive it at %s instead of the path of %s and record the evidence of its inherited modules (%s) in new streams",
			m.Name, m.Path, m.Extends.Source, strings.Join(inherited, ", "))
	}
	return out
}

// CodePolicyStreamForked is the PolicyError code of a module of an extends bundle that does
// not continue the evidence stream of the vendor module at its path (R75). Warning.
const CodePolicyStreamForked = "policy-stream-forked"

// parseRego parses a module as Rego v1, then as Rego v0, as plugins on either OPA major
// would load it; nil when it does not parse or has no package.
func parseRego(p string, src []byte) *ast.Module {
	for _, v := range []ast.RegoVersion{ast.RegoV1, ast.RegoV0} {
		mod, err := ast.ParseModuleWithOpts(p, string(src), ast.ParserOptions{RegoVersion: v})
		if err == nil && mod != nil && mod.Package != nil {
			return mod
		}
	}
	return nil
}

func parseModules(files map[string][]byte) map[string]*ast.Module {
	out := map[string]*ast.Module{}
	for p, src := range files {
		if !strings.HasSuffix(p, ".rego") {
			continue
		}
		if mod := parseRego(p, src); mod != nil {
			out[p] = mod
		}
	}
	return out
}

func packageOf(mod *ast.Module) string {
	if mod == nil || mod.Package == nil {
		return ""
	}
	return strings.TrimPrefix(mod.Package.Path.String(), "data.")
}
