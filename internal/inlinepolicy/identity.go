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

// Evidence identity (R75). A plugin seeds each evidence UUID with the policy's package, its
// file (the path the agent passed the plugin joined with the module's path in the bundle)
// and, through its labels, that path.

// ModuleIdentity is what decides the evidence stream of one policy module.
type ModuleIdentity struct {
	Path    string // slash-separated, relative to the policy root
	Package string // without "data."
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
	var out []ModuleIdentity
	for _, p := range slices.Sorted(maps.Keys(modules)) {
		pkg := packageOf(modules[p])
		if policyeval.IsTestFile(p) || !policyeval.IsPolicyPackage(pkg) {
			continue
		}
		out = append(out, ModuleIdentity{Path: p, Package: pkg})
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

// setViolationSites returns the authored non-test modules of files that define violation as
// a set (`violation contains ...`, R76).
func setViolationSites(files map[string][]byte, authored map[string]bool) []Site {
	var out []Site
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if !authored[p] || !strings.HasSuffix(p, ".rego") || policyeval.IsTestFile(p) {
			continue
		}
		mod := parseRego(p, files[p])
		if mod == nil || !policyeval.IsPolicyPackage(packageOf(mod)) {
			continue
		}
		for _, rule := range mod.Rules {
			if policyeval.RuleName(rule) != "violation" || rule.Head.Key == nil || rule.Head.Value != nil {
				continue
			}
			loc := rule.Head.Location
			if loc == nil {
				loc = rule.Location
			}
			site := Site{Path: p}
			if loc != nil {
				site.Row, site.Col = loc.Row, loc.Col
			}
			out = append(out, site)
			break
		}
	}
	return out
}

// SeedOf returns the evidence seed values (policy_file, _policy_path) of module id when a
// plugin loads it from pluginPath, as policy-manager computes them: OPA gives plugins the
// policy file as the path joined with the module's path (cleaned), and plugins label
// _policy_path with pluginPath as passed.
func SeedOf(id ModuleIdentity, pluginPath string) (string, string) {
	return filepath.Join(pluginPath, filepath.FromSlash(id.Path)), pluginPath
}

// OverrideStreams warns about the authored overrides of an extends bundle that do not keep
// the evidence stream of the vendor module they replace (R75) even when plugins receive the
// bundle at the extends source's path (shadowed): an override at the vendor module's path
// seeds what the vendor module seeds there unless it changes the package
// (policy-package-changed). What not being shadowed costs on top of that is UnshadowedForks.
func OverrideStreams(m *Materialized) []agentconfig.PolicyError {
	if m == nil || m.Extends == nil {
		return nil
	}
	vendor := m.vendorModules()
	var out []agentconfig.PolicyError
	for _, id := range m.Identities {
		v, replaced := vendor[id.Path]
		if !replaced || !m.Authored[id.Path] || id.Package == v.Package {
			continue
		}
		out = append(out, agentconfig.PolicyError{Bundle: m.Name, Path: id.Path, Severity: agentconfig.SeverityWarning, Code: agentconfig.PolicyCodePolicyPackageChanged,
			Message: fmt.Sprintf("the override of %s changes its package from %s to %s, which starts a new evidence stream for it; keep `package %s` to continue the vendor policy's stream",
				id.Path, v.Package, id.Package, v.Package)})
	}
	return out
}

// UnshadowedForks returns the paths of the modules of m that keep the evidence stream of the
// vendor module at their path when plugins receive m at the extends source's path, but not
// at m.Path, where they do when m is not shadowed: inherited modules and overrides that keep
// the vendor's package. Nil when m is shadowed or extends nothing.
func UnshadowedForks(m *Materialized) []string {
	if m == nil || m.Extends == nil || m.Shadowed {
		return nil
	}
	vendor := m.vendorModules()
	var out []string
	for _, id := range m.Identities {
		v, ok := vendor[id.Path]
		if ok && id.Package == v.Package && !sameSeed(id, v, m.Path, m.ExtendsDir) {
			out = append(out, id.Path)
		}
	}
	return out
}

func (m *Materialized) vendorModules() map[string]ModuleIdentity {
	vendor := make(map[string]ModuleIdentity, len(m.ExtendsIdentities))
	for _, id := range m.ExtendsIdentities {
		vendor[id.Path] = id
	}
	return vendor
}

// sameSeed reports whether module id loaded from path seeds evidence like vendor module v
// loaded from vendorPath.
func sameSeed(id, v ModuleIdentity, path, vendorPath string) bool {
	file, policyPath := SeedOf(id, path)
	vendorFile, vendorPolicyPath := SeedOf(v, vendorPath)
	return file == vendorFile && policyPath == vendorPolicyPath
}

// CodePolicyStreamForked is the PolicyError code of the modules of an extends bundle that is
// not shadowed, which do not continue the evidence stream of the vendor module at their path
// (R88). Warning.
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
