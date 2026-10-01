package inlinepolicy

import (
	"fmt"
	"path/filepath"
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
	ids := policyIDs(modules)
	var out []ModuleIdentity
	for _, p := range sortedKeys(modules) {
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
	for _, p := range sortedKeys(files) {
		if !authored[p] || !strings.HasSuffix(p, ".rego") || policyeval.IsTestFile(p) {
			continue
		}
		mod, err := ast.ParseModuleWithOpts(p, string(files[p]), ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil || mod == nil || !policyeval.IsPolicyPackage(packageOf(mod)) {
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
			switch ruleName(rule) {
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

// ContinuityPolicyID is the policy_id that makes a module at rel in a bundle continue the
// stream of the module at rel in the policy path pluginPath when that one has no policy_id:
// the literal pluginPath + "/" + rel (R77), not a cleaned join. policyeval.SeedPath cleans it
// into the policy_file seed, as OPA cleans the file it gives plugins, and trims rel off the
// raw string for the _policy_path seed, which so keeps a non-clean pluginPath such as
// "./policies" or "policies/" as plugins label it. Compare streams with SeedOf, not by
// comparing ids.
func ContinuityPolicyID(pluginPath, rel string) string {
	return pluginPath + "/" + rel
}

// OverrideStreams warns about authored modules of an extends bundle that replace a vendor
// module at the same path but do not continue its evidence stream (R75): a changed package
// (policy-package-changed), or a policy_id that differs from the vendor's, or, when the
// vendor has none, from ContinuityPolicyID of the extends source (policy-stream-forked).
// Plugins that load the bundle in place of the extends source then start a new stream for
// that policy.
func OverrideStreams(m *Materialized) []agentconfig.PolicyError {
	if m == nil || m.Extends == nil {
		return nil
	}
	vendor := map[string]ModuleIdentity{}
	for _, id := range m.ExtendsIdentities {
		vendor[id.Path] = id
	}
	var out []agentconfig.PolicyError
	for _, id := range m.Identities {
		v, replaced := vendor[id.Path]
		if !replaced || !m.Authored[id.Path] {
			continue
		}
		warn := func(code, format string, args ...any) {
			out = append(out, agentconfig.PolicyError{Bundle: m.Name, Path: id.Path, Severity: agentconfig.SeverityWarning, Code: code, Message: fmt.Sprintf(format, args...)})
		}
		if id.Package != v.Package {
			warn(agentconfig.PolicyCodePolicyPackageChanged,
				"the override of %s changes its package from %s to %s, which starts a new evidence stream for it; keep `package %s` to continue the vendor policy's stream",
				id.Path, v.Package, id.Package, v.Package)
			continue
		}
		// Compare what plugins seed with: the vendor module loaded from the extends source,
		// and the override loaded from the bundle's path.
		vendorFile, vendorPath := SeedOf(v, m.ExtendsDir)
		file, policyPath := SeedOf(id, m.Path)
		if file == vendorFile && policyPath == vendorPath {
			continue
		}
		want := v.PolicyID
		if want == "" {
			want = ContinuityPolicyID(m.ExtendsDir, id.Path)
		}
		got := "no policy_id"
		if id.PolicyID != "" {
			got = fmt.Sprintf("policy_id %q", id.PolicyID)
		}
		warn(CodePolicyStreamForked,
			"the override of %s has %s, so plugins that load this bundle instead of %s record its evidence in a new stream; declare `policy_id := %q` to continue the vendor policy's stream",
			id.Path, got, m.Extends.Source, want)
	}
	return out
}

// CodePolicyStreamForked is the PolicyError code of an override whose policy_id does not
// continue the evidence stream of the vendor module it replaces (R75). Warning.
const CodePolicyStreamForked = "policy-stream-forked"

func parseModules(files map[string][]byte) map[string]*ast.Module {
	out := map[string]*ast.Module{}
	for p, src := range files {
		if !strings.HasSuffix(p, ".rego") {
			continue
		}
		mod, err := ast.ParseModuleWithOpts(p, string(src), ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err == nil && mod != nil && mod.Package != nil {
			out[p] = mod
		}
	}
	return out
}

// policyIDs returns each package's policy_id: set when the package declares exactly one
// policy_id rule, as an unconditional literal that policyeval.ValidPolicyID accepts.
func policyIDs(modules map[string]*ast.Module) map[string]string {
	rules := map[string][]*ast.Rule{}
	for p, mod := range modules {
		if policyeval.IsTestFile(p) {
			continue
		}
		for _, rule := range mod.Rules {
			if ruleName(rule) == "policy_id" {
				pkg := packageOf(mod)
				rules[pkg] = append(rules[pkg], rule)
			}
		}
	}
	out := map[string]string{}
	for pkg, rs := range rules {
		if len(rs) != 1 {
			continue
		}
		if id, ok := literalPolicyID(rs[0]); ok {
			out[pkg] = id
		}
	}
	return out
}

func literalPolicyID(rule *ast.Rule) (string, bool) {
	if len(rule.Head.Ref()) != 1 || len(rule.Head.Args) > 0 || rule.Head.Key != nil || rule.Head.Value == nil ||
		rule.Default || rule.Else != nil || !unconditional(rule) {
		return "", false
	}
	s, ok := rule.Head.Value.Value.(ast.String)
	if !ok || !policyeval.ValidPolicyID(string(s)) {
		return "", false
	}
	return string(s), true
}

func unconditional(rule *ast.Rule) bool {
	if len(rule.Body) != 1 {
		return false
	}
	expr := rule.Body[0]
	if expr.Negated || len(expr.With) > 0 {
		return false
	}
	term, ok := expr.Terms.(*ast.Term)
	return ok && term.Value.Compare(ast.Boolean(true)) == 0
}

func ruleName(rule *ast.Rule) string {
	ref := rule.Head.Ref()
	if len(ref) == 0 {
		return ""
	}
	if v, ok := ref[0].Value.(ast.Var); ok {
		return string(v)
	}
	return ""
}

func packageOf(mod *ast.Module) string {
	if mod == nil || mod.Package == nil {
		return ""
	}
	return strings.TrimPrefix(mod.Package.Path.String(), "data.")
}
