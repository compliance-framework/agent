package inlinepolicy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/agentconfig/regocheck"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// The policy contract checks (R63). The API's regocheck runs the static contract check on
// the authored modules of every bundle before materialization; here the agent adds what only
// it can see, on the materialized tree:
//
//   - static: policyeval.CheckContract on the tree: every issue of the packages no authored
//     module touches (vendor debt: warnings only, R21/R34), and duplicate non-test modules
//     of authored packages;
//   - dynamic: a sandboxed dry run on an empty input through policyeval's Execute and
//     policy-manager's GetRiskTemplates, exactly the calls plugins make. Problems in a
//     package that contains an authored module are errors (as the contract rates them);
//     in vendor-only packages they are warnings. Evaluation conflicts on {} are warnings:
//     the real input may never trigger them.

// treePackages maps every .rego file of the tree (relative path) to its package, without
// "data.".
type treePackages map[string]string

func packagesOf(modules map[string]*ast.Module, root string) treePackages {
	out := treePackages{}
	for path, mod := range modules {
		if mod != nil && mod.Package != nil {
			out[relPath(root, path)] = packageOf(mod)
		}
	}
	return out
}

// authoredPackages returns the packages that contain an authored non-test module. An
// authored test alone does not make a vendor package authored: adding a test must not turn
// the vendor's contract debt into errors.
func (p treePackages) authoredPackages(authored map[string]bool) map[string]bool {
	out := map[string]bool{}
	for file, pkg := range p {
		if authored[file] && !policyeval.IsTestFile(file) {
			out[pkg] = true
		}
	}
	return out
}

// filesOf returns the sorted files defining pkg, optionally only authored or only non-test ones.
func (p treePackages) filesOf(pkg string, keep func(file string) bool) []string {
	var out []string
	for file, fp := range p {
		if fp == pkg && (keep == nil || keep(file)) {
			out = append(out, file)
		}
	}
	slices.Sort(out)
	return out
}

// overrideHint explains a compile error in a vendor file whose package an authored module
// also defines (R65): usually an override removed a rule the vendor's test still uses.
func overrideHint(file string, pkgs treePackages, authored map[string]bool) string {
	pkg, ok := pkgs[file]
	if !ok || file == "" || authored[file] {
		return ""
	}
	overrides := pkgs.filesOf(pkg, func(f string) bool { return authored[f] })
	if len(overrides) == 0 {
		return ""
	}
	kind := "vendor module"
	if policyeval.IsTestFile(file) {
		kind = "vendor test"
	}
	quoted := make([]string, len(overrides))
	for i, f := range overrides {
		quoted[i] = "`" + f + "`"
	}
	return fmt.Sprintf("%s references rules removed by the override of %s; keep the rule or add `delete: [%s]`", kind, strings.Join(quoted, ", "), file)
}

// staticContract runs the static contract check: every issue of the packages no authored
// module touches (vendor debt, warnings), and duplicate-package-module for the packages an
// authored module is in, which regocheck cannot see because it only has the authored modules
// (it checked the rest of the contract on them). It returns the issues and the (package,
// code) pairs it reported for vendor packages, so the dry run does not repeat them.
func staticContract(in CheckInput, modules map[string]*ast.Module, authoredPkgs map[string]bool) ([]agentconfig.PolicyError, map[[2]string]bool) {
	vendor, authored := map[string]*ast.Module{}, map[string]*ast.Module{}
	for path, mod := range modules {
		if authoredPkgs[packageOf(mod)] {
			authored[path] = mod
		} else {
			vendor[path] = mod
		}
	}
	var out []agentconfig.PolicyError
	add := func(issue policyeval.Issue, suffix string) {
		e := regocheck.ToPolicyError(in.Bundle, issue)
		e.Path = relPath(in.PolicyDir, issue.File)
		e.Message = strings.ReplaceAll(e.Message, in.PolicyDir+string(filepath.Separator), "") + suffix
		e.Severity = agentconfig.SeverityWarning
		out = append(out, e)
	}
	seen := map[[2]string]bool{}
	for _, issue := range policyeval.CheckContract(vendor) {
		seen[[2]string{issue.Package, issue.Code}] = true
		add(issue, " (vendor package: a warning only)")
	}
	for _, issue := range policyeval.CheckContract(authored) {
		if issue.Code == agentconfig.PolicyCodeDuplicatePackageModule {
			add(issue, "")
		}
	}
	return out, seen
}

// Codes of the dry-run problems that are not policyeval contract issues.
const (
	codeEvalError     = "eval-error"
	codeEvalConflict  = "eval-conflict"
	codeDryRunTimeout = "dry-run-timeout"
)

// evalLocation matches the package and file policyeval.Execute names in its decode errors.
var evalLocation = regexp.MustCompile(` ?\(policy package "([^"]+)", file "([^"]*)"\)`)

// dryRun evaluates the tree on an empty input the way a plugin does, sandboxed: denied
// builtins are rewritten to erroring stubs and the evaluator only has
// policyeval.SandboxCapabilities, so nothing reaches the network or the host. A package
// whose evaluation fails is reported and left out of the next attempt, so one broken
// package does not hide the others.
func dryRun(ctx context.Context, in CheckInput, b *bundle.Bundle, pkgs treePackages, authoredPkgs map[string]bool, vendorSeen map[[2]string]bool) []agentconfig.PolicyError {
	ctx, cancel := context.WithTimeout(ctx, TestTimeout)
	defer cancel()

	parsed := make(map[string]*ast.Module, len(b.Modules))
	for _, mf := range b.Modules {
		parsed[mf.Path] = mf.Parsed
	}
	sandboxed, stubs, caps := sandboxTestModules(parsed)

	var out []agentconfig.PolicyError
	seen := map[string]bool{} // package + code + message
	riskReported := map[string]bool{}
	add := func(pkg, file, code, severity, msg string) {
		key := pkg + "\x00" + code + "\x00" + msg
		if seen[key] {
			return
		}
		seen[key] = true
		if code == agentconfig.PolicyCodeInvalidRiskTemplate || strings.Contains(msg, "risk_templates") {
			riskReported[pkg] = true
		}
		out = append(out, agentconfig.PolicyError{
			Bundle:   in.Bundle,
			Path:     file,
			Message:  prefixPlugin(in.Plugin, "on an empty input: "+msg),
			Severity: severity,
			Code:     code,
		})
	}
	severityFor := func(pkg string) string {
		if authoredPkgs[pkg] {
			return agentconfig.SeverityError
		}
		return agentconfig.SeverityWarning
	}

	excluded := map[string]bool{}
	evaluator := func() (*policyeval.Evaluator, bool) {
		dry := &bundle.Bundle{Data: b.Data, Manifest: b.Manifest.Copy()}
		dry.Manifest.Init()
		policies := false
		for _, mf := range b.Modules {
			pkg := pkgs[relPath(in.PolicyDir, mf.Path)]
			if excluded[pkg] {
				continue
			}
			mf.Parsed = sandboxed[mf.Path]
			dry.Modules = append(dry.Modules, mf)
			if policyeval.IsPolicyPackage(pkg) && !policyeval.IsTestFile(mf.Path) {
				policies = true
			}
		}
		loaders := []func(*rego.Rego){rego.ParsedBundle("inline", dry)}
		for _, s := range stubs {
			loaders = append(loaders, s.Func)
		}
		return policyeval.NewWithLoaders(loaders, in.PolicyData, policyeval.Options{Capabilities: caps}), policies
	}

	// failure reports err and returns the package to leave out, or "" to stop.
	failure := func(err error, code string) string {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				// Not attributable to authored Rego (vendor packages are evaluated too), so
				// never a reason to reject.
				add("", "", codeDryRunTimeout, agentconfig.SeverityWarning, fmt.Sprintf("the dry run timed out after %s; the policy contract was not fully checked", TestTimeout))
			}
			return ""
		}
		pkg, file := locateEvalError(err, in.PolicyDir, pkgs)
		severity := severityFor(pkg)
		var te *topdown.Error
		switch msg := err.Error(); {
		case errors.As(err, &te) && te.Code == topdown.ConflictErr:
			severity = agentconfig.SeverityWarning
			code = codeEvalConflict
		case strings.Contains(msg, "decode violation entry") || strings.Contains(msg, "unexpected violations type"):
			code = agentconfig.PolicyCodeInvalidViolation
		case strings.Contains(msg, "decode policy outputs") || strings.Contains(msg, "expected module outputs"):
			code = agentconfig.PolicyCodeInvalidType
		}
		if pkg == "" {
			// Not attributable to a package: never reject on it.
			add("", file, code, agentconfig.SeverityWarning, "could not evaluate the bundle: "+err.Error())
			return ""
		}
		if severity == agentconfig.SeverityWarning && vendorSeen[[2]string{pkg, code}] {
			return pkg
		}
		msg := evalLocation.ReplaceAllString(err.Error(), "")
		add(pkg, file, code, severity, fmt.Sprintf("package %s: %s", pkg, strings.ReplaceAll(msg, in.PolicyDir+string(filepath.Separator), "")))
		return pkg
	}

	var ev *policyeval.Evaluator
	for range len(pkgs) + 1 {
		var policies bool
		if ev, policies = evaluator(); !policies {
			return out
		}
		results, err := ev.Execute(ctx, map[string]any{})
		if err != nil {
			pkg := failure(err, codeEvalError)
			if pkg == "" || excluded[pkg] {
				return out
			}
			excluded[pkg] = true
			continue
		}
		for _, r := range results {
			pkg := r.Policy.Package.PurePackage()
			file := relPath(in.PolicyDir, r.Policy.File)
			for _, issue := range r.Issues {
				severity := issue.Severity
				msg := issue.Message
				if !authoredPkgs[pkg] {
					if vendorSeen[[2]string{pkg, issue.Code}] {
						continue
					}
					severity = agentconfig.SeverityWarning
				}
				if issue.Code == agentconfig.PolicyCodeMissingTitle && hasRule(parsed, pkg, "title") {
					// The title depends on the input; the static check rates that a warning.
					severity = agentconfig.SeverityWarning
				}
				add(pkg, file, issue.Code, severity, msg)
			}
		}
		break
	}

	// Risk templates, through the same call plugins make at Init.
	for range len(pkgs) + 1 {
		if ev == nil {
			break
		}
		_, err := policyManager.NewWithEvaluator(hclog.NewNullLogger(), ev).GetRiskTemplates(ctx)
		if err == nil {
			break
		}
		var rte *policyManager.RiskTemplateError
		if errors.As(err, &rte) && riskReported[rte.Package] {
			// ValidateResult already reported this package's risk templates.
			excluded[rte.Package] = true
		} else {
			pkg := failure(err, agentconfig.PolicyCodeInvalidRiskTemplate)
			if pkg == "" || excluded[pkg] {
				break
			}
			excluded[pkg] = true
		}
		var policies bool
		if ev, policies = evaluator(); !policies {
			break
		}
	}
	return out
}

// locateEvalError finds the package (without "data.") and file an evaluation error is about.
func locateEvalError(err error, root string, pkgs treePackages) (pkg, file string) {
	var rte *policyManager.RiskTemplateError
	if errors.As(err, &rte) {
		return rte.Package, relPath(root, rte.File)
	}
	var te *topdown.Error
	if errors.As(err, &te) && te.Location != nil && te.Location.File != "" {
		file = relPath(root, te.Location.File)
		return pkgs[file], file
	}
	if m := evalLocation.FindStringSubmatch(err.Error()); m != nil {
		return strings.TrimPrefix(m[1], "data."), relPath(root, m[2])
	}
	return "", ""
}

// hasRule reports whether any module of pkg defines a rule named name.
func hasRule(modules map[string]*ast.Module, pkg, name string) bool {
	for _, mod := range modules {
		if packageOf(mod) != pkg {
			continue
		}
		for _, rule := range mod.Rules {
			if policyeval.RuleName(rule) == name {
				return true
			}
		}
	}
	return false
}
