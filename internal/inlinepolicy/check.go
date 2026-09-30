package inlinepolicy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/tester"
)

// TestTimeout bounds the Rego tests of one (plugin, policy path) check.
var TestTimeout = 30 * time.Second

// CheckInput is one plugin × materialized policy path.
type CheckInput struct {
	Plugin, Bundle string
	PolicyDir      string
	Authored       map[string]bool
	AuthoredTests  []string
	PolicyData     map[string]any
}

// Check compiles and tests one materialized bundle exactly the way a plugin will load it
// (R3, R21): one compile unit per policy path, through the same policyeval constructor and
// prepare path policy-manager uses. It returns errors (the revision is rejected) and warnings:
//
//  1. parity compile: every compile error is an error;
//  2. denied builtins (R19, R20): any policyeval.DeniedBuiltins ref reachable from an authored
//     rule through the compiled rule graph — including `with f as http.send` — is an error;
//  3. tests: a failing authored _test.rego test is an error, a failing vendor test a warning.
//     Tests never run when step 2 found a denied builtin, and they run sandboxed: a denied
//     builtin can never execute on the agent host (D17, HLD §8).
//
// The parse-level checks (regocheck) run once per bundle before materialization.
func Check(ctx context.Context, in CheckInput) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	add := func(severity string, loc *ast.Location, format string, args ...any) {
		e := agentconfig.PolicyError{Bundle: in.Bundle, Message: fmt.Sprintf(format, args...), Severity: severity}
		if in.Plugin != "" {
			e.Message = fmt.Sprintf("plugin %s: %s", in.Plugin, e.Message)
		}
		if loc != nil {
			e.Path = relPath(in.PolicyDir, loc.File)
			e.Row, e.Col = loc.Row, loc.Col
		}
		out = append(out, e)
	}

	// 1. Parity compile.
	_, err := policyeval.NewFromBundlePath(in.PolicyDir, in.PolicyData, policyeval.Options{}).
		PrepareForEval(ctx, rego.Query("data.compliance_framework"), rego.Package("compliance_framework"))
	if err != nil {
		addCompileErrors(err, func(loc *ast.Location, msg string) {
			add(agentconfig.SeverityError, loc, "%s", strings.ReplaceAll(msg, in.PolicyDir+string(filepath.Separator), ""))
		})
		agentconfig.SortPolicyErrors(out)
		return out
	}

	b, err := loader.NewFileLoader().WithRegoVersion(ast.RegoV1).AsBundle(in.PolicyDir)
	if err != nil {
		add(agentconfig.SeverityError, nil, "load bundle: %s", err.Error())
		return out
	}
	modules := make(map[string]*ast.Module, len(b.Modules))
	for _, mf := range b.Modules {
		modules[mf.Path] = mf.Parsed
	}
	compiler := ast.NewCompiler()
	if compiler.Compile(modules); compiler.Failed() {
		addCompileErrors(compiler.Errors, func(loc *ast.Location, msg string) { add(agentconfig.SeverityError, loc, "%s", msg) })
		agentconfig.SortPolicyErrors(out)
		return out
	}

	// 2. Transitive denied builtins. The revision is rejected, so the tests (which would
	// execute the denied builtin) never run.
	hits := deniedReachable(compiler, in.PolicyDir, in.Authored)
	for _, h := range hits {
		add(agentconfig.SeverityError, h.loc, "forbidden builtin %s is reachable from authored rule %s", h.name, h.from)
	}
	if len(hits) > 0 {
		agentconfig.SortPolicyErrors(out)
		return out
	}

	// 3. Tests.
	out = append(out, runTests(ctx, in, b.Data, modules)...)
	agentconfig.SortPolicyErrors(out)
	return out
}

func addCompileErrors(err error, add func(loc *ast.Location, msg string)) {
	var astErrs ast.Errors
	switch e := err.(type) {
	case ast.Errors:
		astErrs = e
	case *ast.Error:
		astErrs = ast.Errors{e}
	default:
		var single *ast.Error
		if errors.As(err, &astErrs) {
			break
		}
		if errors.As(err, &single) {
			astErrs = ast.Errors{single}
		}
	}
	if len(astErrs) == 0 {
		add(nil, err.Error())
		return
	}
	for _, e := range astErrs {
		add(e.Location, e.Message)
	}
}

// relPath makes a module file path relative to the policy root (slash-separated).
func relPath(root, file string) string {
	if file == "" {
		return ""
	}
	if rel, err := filepath.Rel(root, file); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(file)
}

type deniedHit struct {
	name string
	loc  *ast.Location
	from string
}

// deniedReachable walks every rule of the authored modules and, through data refs, every rule
// they can reach, and reports each denied builtin ref (calls, `with ... as <denied>`, any
// position).
func deniedReachable(c *ast.Compiler, root string, authored map[string]bool) []deniedHit {
	var hits []deniedHit
	seenHit := map[string]bool{}
	visited := map[*ast.Rule]bool{}
	opts := ast.RulesOptions{IncludeHiddenModules: true}

	var visit func(rule *ast.Rule, from string)
	visit = func(rule *ast.Rule, from string) {
		if visited[rule] {
			return
		}
		visited[rule] = true
		ast.WalkRefs(rule, func(ref ast.Ref) bool {
			if len(ref) == 0 {
				return false
			}
			name := ref.String()
			if slices.Contains(policyeval.DeniedBuiltins, name) {
				loc := ref[0].Location
				key := name
				if loc != nil {
					key = fmt.Sprintf("%s:%s:%d:%d", name, loc.File, loc.Row, loc.Col)
				}
				if !seenHit[key] {
					seenHit[key] = true
					hits = append(hits, deniedHit{name: name, loc: loc, from: from})
				}
				return false
			}
			if ref.HasPrefix(ast.DefaultRootRef) {
				for _, r := range c.GetRulesDynamicWithOpts(ref, opts) {
					visit(r, from)
				}
			}
			return false
		})
		if rule.Else != nil {
			visit(rule.Else, from)
		}
	}

	for _, path := range sortedKeys(c.Modules) {
		if !authored[relPath(root, path)] {
			continue
		}
		mod := c.Modules[path]
		for _, rule := range mod.Rules {
			from := strings.TrimPrefix(rule.Ref().String(), "data.")
			if mod.Package != nil {
				from = strings.TrimPrefix(mod.Package.Path.String(), "data.") + "." + rule.Head.Ref().String()
			}
			visit(rule, from)
		}
	}
	return hits
}

// runTests runs the bundle's Rego tests against the bundle data merged with the plugin's
// policy_data. Authored test failures are errors, vendor test failures warnings (R21).
func runTests(ctx context.Context, in CheckInput, bundleData map[string]any, modules map[string]*ast.Module) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	testCtx, cancel := context.WithTimeout(ctx, TestTimeout)
	defer cancel()
	store := inmem.NewFromObject(mergePolicyData(bundleData, in.PolicyData))
	sandboxed, stubs, caps := sandboxTestModules(modules)
	ch, err := tester.NewRunner().
		SetCompiler(ast.NewCompiler().WithCapabilities(caps)).
		AddCustomBuiltins(stubs).
		SetStore(store).
		SetModules(sandboxed).
		SetTimeout(TestTimeout).
		RunTests(testCtx, nil)
	if err != nil {
		return []agentconfig.PolicyError{{Bundle: in.Bundle, Message: prefixPlugin(in.Plugin, "run tests: "+err.Error()), Severity: agentconfig.SeverityError}}
	}
	for res := range ch {
		if res == nil || res.Pass() || res.Skip {
			continue
		}
		e := agentconfig.PolicyError{Bundle: in.Bundle, Severity: agentconfig.SeverityWarning}
		if res.Location != nil {
			e.Path = relPath(in.PolicyDir, res.Location.File)
			e.Row, e.Col = res.Location.Row, res.Location.Col
		}
		if in.Authored[e.Path] || slices.Contains(in.AuthoredTests, e.Path) {
			e.Severity = agentconfig.SeverityError
		}
		msg := fmt.Sprintf("test %s.%s failed", strings.TrimPrefix(res.Package, "data."), res.Name)
		if res.Error != nil {
			msg = fmt.Sprintf("test %s.%s errored: %v", strings.TrimPrefix(res.Package, "data."), res.Name, res.Error)
		}
		e.Message = prefixPlugin(in.Plugin, msg)
		out = append(out, e)
	}
	if testCtx.Err() != nil && ctx.Err() == nil {
		out = append(out, agentconfig.PolicyError{Bundle: in.Bundle, Message: prefixPlugin(in.Plugin, fmt.Sprintf("tests timed out after %s", TestTimeout)), Severity: agentconfig.SeverityError})
	}
	return out
}

// deniedStubPrefix names the stand-ins for denied builtins in sandboxed test runs.
const deniedStubPrefix = "ccf_denied_builtin."

// sandboxTestModules returns copies of modules in which every denied builtin ref (a call,
// `with ... as <denied>`, any position) is rewritten to a stub builtin that always errors,
// the stubs, and capabilities without the denied builtins (policyeval.SandboxCapabilities)
// plus the stubs. A denied builtin therefore can never execute during tests: whatever the
// rewrite misses fails to compile instead. Vendor modules that merely reference a denied
// builtin off the authored path still compile, and their tests fail (as warnings).
func sandboxTestModules(modules map[string]*ast.Module) (map[string]*ast.Module, []*tester.Builtin, *ast.Capabilities) {
	caps := policyeval.SandboxCapabilities()
	stubNames := map[string]ast.Ref{}
	var stubs []*tester.Builtin
	for _, name := range policyeval.DeniedBuiltins {
		decl, ok := ast.BuiltinMap[name]
		if !ok {
			continue
		}
		stubName := deniedStubPrefix + strings.ReplaceAll(name, ".", "_")
		stubDecl := &ast.Builtin{Name: stubName, Decl: decl.Decl}
		caps.Builtins = append(caps.Builtins, stubDecl)
		stubNames[name] = ast.MustParseRef(stubName)
		denied := name
		stubs = append(stubs, &tester.Builtin{
			Decl: stubDecl,
			Func: rego.FunctionDyn(&rego.Function{Name: stubName, Decl: decl.Decl}, func(rego.BuiltinContext, []*ast.Term) (*ast.Term, error) {
				return nil, fmt.Errorf("%s is not available in inline policy tests", denied)
			}),
		})
	}

	out := make(map[string]*ast.Module, len(modules))
	for path, mod := range modules {
		cp := mod.Copy()
		res, err := ast.TransformRefs(cp, func(ref ast.Ref) (ast.Value, error) {
			if stub, ok := stubNames[ref.String()]; ok {
				return stub.Copy(), nil
			}
			return ref, nil
		})
		if m, ok := res.(*ast.Module); ok && err == nil {
			cp = m
		}
		out[path] = cp
	}
	return out, stubs, caps
}

func prefixPlugin(plugin, msg string) string {
	if plugin == "" {
		return msg
	}
	return fmt.Sprintf("plugin %s: %s", plugin, msg)
}

// mergePolicyData mirrors policyeval's unexported writePolicyData: nested maps merge
// recursively, anything else replaces.
func mergePolicyData(base, overlay map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		if vm, ok := v.(map[string]any); ok {
			if bm, ok := out[k].(map[string]any); ok {
				out[k] = mergePolicyData(bm, vm)
				continue
			}
		}
		out[k] = v
	}
	return out
}
