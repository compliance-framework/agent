package inlinepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/open-policy-agent/opa/v1/rego"
)

// vendorTree writes files under a new directory and returns a resolver serving it.
func vendorTree(t *testing.T, files map[string]string) (string, Resolver) {
	t.Helper()
	dir := t.TempDir()
	for p, content := range files {
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, func(_ context.Context, source string) (string, error) {
		if source != "ghcr.io/vendor/policies:v1" {
			return "", errors.New("unknown source " + source)
		}
		return dir, nil
	}
}

func strptr(s string) *string { return &s }

func readFile(t *testing.T, dir, p string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p)))
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(raw)
}

const vendorBanner = "package compliance_framework.banner\n\ntitle := \"Banner\"\n\nviolation contains {\"id\": \"no-banner\", \"remarks\": \"no banner\"} if not input.banner\n"
const vendorMaxAuth = "package compliance_framework.max_auth\n\nviolation contains {\"remarks\": \"too many\"} if input.max_auth > 3\n"

func TestMaterialize_R17Order(t *testing.T) {
	_, resolve := vendorTree(t, map[string]string{
		"banner.rego":          vendorBanner,
		"max_auth.rego":        vendorMaxAuth,
		"legacy.rego":          "package compliance_framework.legacy\n",
		"data.yaml":            "limits:\n  max_auth: 3\n  keep: true\n",
		"lib/helpers.rego":     "package ccf_libs.helpers\n",
		"lib/ignored.json":     "{}",
		"banner_test.rego":     "package compliance_framework.banner_test\n",
		"sub/data.json":        `{"x": 1}`,
		"docs/README.md":       "# vendor",
		"max_auth_test.rego":   "package compliance_framework.max_auth_test\n",
		"nested/deep/a.rego":   "package compliance_framework.a\n",
		"nested/deep/data.yml": "k: v\n",
	})
	b := &agentconfig.PolicyBundle{
		Extends: strptr("ghcr.io/vendor/policies:v1"),
		Delete:  []string{"legacy.rego", "missing.rego"},
		Modules: map[string]string{
			"max_auth.rego":          "package compliance_framework.max_auth\n# override\n",
			"extra/new.rego":         "package compliance_framework.extra\n",
			"Policies/Max.Auth.rego": "package compliance_framework.mixed\n",
		},
		Data: map[string]any{"limits": map[string]any{"max_auth": 5, "keep": nil}},
	}
	root := t.TempDir()
	m, err := Materialize(context.Background(), root, "ssh", b, resolve)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "legacy.rego")); !os.IsNotExist(err) {
		t.Fatal("deleted vendor module must be gone")
	}
	if got := readFile(t, m.Dir, "max_auth.rego"); !strings.Contains(got, "# override") {
		t.Fatalf("override not applied: %q", got)
	}
	if got := readFile(t, m.Dir, "banner.rego"); got != vendorBanner {
		t.Fatalf("inherited module changed: %q", got)
	}
	readFile(t, m.Dir, "extra/new.rego")
	readFile(t, m.Dir, "Policies/Max.Auth.rego")
	var data map[string]any
	if err := json.Unmarshal([]byte(readFile(t, m.Dir, "data.json")), &data); err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"limits": map[string]any{"max_auth": float64(5)}}; !reflect.DeepEqual(data, want) {
		t.Fatalf("data.yaml must be merge-patched into data.json: %#v", data)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "data.yaml")); !os.IsNotExist(err) {
		t.Fatal("the root data.yaml must be replaced by data.json")
	}
	var warned []string
	for _, w := range m.Warnings {
		warned = append(warned, w.Path)
	}
	if !contains(warned, "missing.rego") || !contains(warned, "lib/ignored.json") {
		t.Fatalf("expected warnings for the missing delete and the stray vendor data file, got %v", warned)
	}
	if !m.Authored["max_auth.rego"] || m.Authored["banner.rego"] || !m.Authored["data.json"] {
		t.Fatalf("authored set wrong: %v", m.Authored)
	}
	if m.Extends == nil || m.Extends.Source != "ghcr.io/vendor/policies:v1" || len(m.Extends.Files) != 12 {
		t.Fatalf("extends report wrong: %+v", m.Extends)
	}
	if !strings.HasPrefix(m.Digest, agentconfig.TreeDigestPrefix) || filepath.Base(filepath.Dir(m.Dir)) != strings.TrimPrefix(m.Digest, agentconfig.TreeDigestPrefix) {
		t.Fatalf("digest/dir mismatch: %s %s", m.Digest, m.Dir)
	}
	for _, f := range m.Files {
		if f.Path == "banner.rego" && f.Package != "compliance_framework.banner" {
			t.Fatalf("package not inventoried: %+v", f)
		}
	}

	again, err := Materialize(context.Background(), root, "ssh", b, resolve)
	if err != nil || again.Dir != m.Dir {
		t.Fatalf("the same content must reuse the same directory: %v %s %s", err, again.Dir, m.Dir)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestMaterialize_OverlayNullRestoresVendorModule(t *testing.T) {
	_, resolve := vendorTree(t, map[string]string{"max_auth.rego": vendorMaxAuth})
	base := agentconfig.Config{PolicyBundles: map[string]*agentconfig.PolicyBundle{"ssh": {
		Extends: strptr("ghcr.io/vendor/policies:v1"),
		Modules: map[string]string{"max_auth.rego": "package compliance_framework.max_auth\n# file override\n"},
	}}}
	merged, err := agentconfig.Merge(base, json.RawMessage(`{"policy_bundles":{"ssh":{"modules":{"max_auth.rego":null}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Materialize(context.Background(), t.TempDir(), "ssh", merged.PolicyBundles["ssh"], resolve)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, m.Dir, "max_auth.rego"); got != vendorMaxAuth {
		t.Fatalf("null must restore the vendor module, got %q", got)
	}
}

func TestMaterialize_Errors(t *testing.T) {
	_, resolve := vendorTree(t, map[string]string{"a.rego": "package compliance_framework.a\n"})
	tests := []struct {
		name string
		b    *agentconfig.PolicyBundle
	}{
		{"data and data.json", &agentconfig.PolicyBundle{Modules: map[string]string{"data.json": "{}"}, Data: map[string]any{"a": 1}}},
		{"stray json module", &agentconfig.PolicyBundle{Modules: map[string]string{"foo.json": "{}"}}},
		{"parent path", &agentconfig.PolicyBundle{Modules: map[string]string{"../x.rego": "package x"}}},
		{"absolute path", &agentconfig.PolicyBundle{Modules: map[string]string{"/abs.rego": "package x"}}},
		{"escaping path", &agentconfig.PolicyBundle{Modules: map[string]string{"a/../../x.rego": "package x"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Materialize(context.Background(), t.TempDir(), "b", tt.b, resolve)
			var perrs PolicyErrors
			if !errors.As(err, &perrs) || !agentconfig.HasPolicyErrors(perrs) {
				t.Fatalf("expected policy errors, got %v", err)
			}
		})
	}
	t.Run("resolver failure", func(t *testing.T) {
		_, err := Materialize(context.Background(), t.TempDir(), "b", &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/other:v1")}, resolve)
		if !errors.Is(err, ErrResolve) {
			t.Fatalf("expected ErrResolve, got %v", err)
		}
	})
}

func TestMaterialize_ExtendsRootSymlinkAndEmptyTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	t.Run("symlinked root is followed", func(t *testing.T) {
		vendorDir, _ := vendorTree(t, map[string]string{"banner.rego": vendorBanner, "lib/x.rego": "package lib.x\n"})
		link := filepath.Join(t.TempDir(), "policies")
		if err := os.Symlink(vendorDir, link); err != nil {
			t.Fatal(err)
		}
		resolve := func(context.Context, string) (string, error) { return link, nil }
		m, err := Materialize(context.Background(), t.TempDir(), "b", &agentconfig.PolicyBundle{Extends: strptr("/etc/ccf/policies")}, resolve)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Extends.Files) != 2 || len(m.Warnings) != 0 {
			t.Fatalf("expected both vendor files through the symlinked root, got %+v (warnings %+v)", m.Extends.Files, m.Warnings)
		}
	})
	t.Run("a tree without .rego files is an error", func(t *testing.T) {
		_, resolve := vendorTree(t, map[string]string{"README.md": "nothing here"})
		_, err := Materialize(context.Background(), t.TempDir(), "b", &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1")}, resolve)
		if !errors.Is(err, ErrResolve) || !strings.Contains(err.Error(), "no .rego files") {
			t.Fatalf("expected an ErrResolve for an empty extends tree, got %v", err)
		}
	})
}

func TestMaterialize_SkipsSymlinksInExtends(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	dir, resolve := vendorTree(t, map[string]string{"a.rego": "package compliance_framework.a\n"})
	secret := filepath.Join(t.TempDir(), "secret.rego")
	if err := os.WriteFile(secret, []byte("package secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "link.rego")); err != nil {
		t.Fatal(err)
	}
	m, err := Materialize(context.Background(), t.TempDir(), "b", &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1")}, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(m.Dir, "link.rego")); !os.IsNotExist(err) {
		t.Fatal("a symlink must not be materialized")
	}
	if len(m.Warnings) != 1 || m.Warnings[0].Path != "link.rego" {
		t.Fatalf("expected a symlink warning, got %+v", m.Warnings)
	}
}

func materialize(t *testing.T, vendor map[string]string, b *agentconfig.PolicyBundle) *Materialized {
	t.Helper()
	_, resolve := vendorTree(t, vendor)
	m, err := Materialize(context.Background(), t.TempDir(), "b", b, resolve)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	return m
}

func check(m *Materialized, policyData map[string]any) []agentconfig.PolicyError {
	return Check(context.Background(), CheckInput{Plugin: "ssh", Bundle: m.Name, PolicyDir: m.Dir, Authored: m.Authored, AuthoredTests: m.AuthoredTests, PolicyData: policyData})
}

func errorsOf(errs []agentconfig.PolicyError, severity string) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	for _, e := range errs {
		if e.Severity == severity {
			out = append(out, e)
		}
	}
	return out
}

func TestCheck_CompileAndBuiltins(t *testing.T) {
	vendor := map[string]string{
		"lib/net.rego": "package ccf_libs.net\n\nfetch(u) := http.send({\"method\": \"GET\", \"url\": u})\n\nhelper(x) := x\n",
		"banner.rego":  vendorBanner,
	}
	tests := []struct {
		name    string
		modules map[string]string
		wantErr string
	}{
		{"parse error", map[string]string{"bad.rego": "package compliance_framework.bad\n\nviolation contains x if {"}, "bad.rego"},
		{"direct http.send is located", map[string]string{"x.rego": "package compliance_framework.x\n\nr := http.send({\"method\": \"GET\", \"url\": \"http://x\"})\n"}, "x.rego:3"},
		{"direct http.send", map[string]string{"x.rego": "package compliance_framework.x\n\nr := http.send({\"method\": \"GET\", \"url\": \"http://x\"})\n"}, "http.send"},
		{"vendor helper wrapping http.send", map[string]string{"x.rego": "package compliance_framework.x\n\nimport data.ccf_libs.net\n\nr := net.fetch(\"http://x\")\n"}, "http.send"},
		{"with f as http.send", map[string]string{"x.rego": "package compliance_framework.x\n\nimport data.ccf_libs.net\n\nr if {\n\tnet.helper(1) with net.helper as http.send\n}\n"}, "reachable from authored rule"},
		{"import from another policy path", map[string]string{"x.rego": "package compliance_framework.x\n\nimport data.other_bundle.lib\n\nr := lib.f(1)\n"}, "x.rego"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Modules: tt.modules})
			errs := errorsOf(check(m, nil), agentconfig.SeverityError)
			if len(errs) == 0 {
				t.Fatal("expected an error")
			}
			joined := PolicyErrors(errs).Error()
			if !strings.Contains(joined, tt.wantErr) {
				t.Fatalf("error %q does not mention %q", joined, tt.wantErr)
			}
		})
	}

	t.Run("pure builtins are allowed", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n\na := net.cidr_contains(\"10.0.0.0/8\", \"10.1.2.3\")\n\nb := rego.parse_module(\"x.rego\", \"package x\")\n\nc if trace(\"hi\")\n",
		}})
		if errs := errorsOf(check(m, nil), agentconfig.SeverityError); len(errs) != 0 {
			t.Fatalf("unexpected errors %v", errs)
		}
	})

	t.Run("vendor-only denied builtins are not attributed to authored rules", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\nimport data.ccf_libs.net\n\ntitle := \"x\"\n\nr := net.helper(1)\n",
		}})
		if errs := errorsOf(check(m, nil), agentconfig.SeverityError); len(errs) != 0 {
			t.Fatalf("unexpected errors %v", errs)
		}
	})

	t.Run("manifest roots excluding the inline package", func(t *testing.T) {
		m := materialize(t, map[string]string{
			".manifest":   `{"roots": ["compliance_framework/banner"]}`,
			"banner.rego": vendorBanner,
		}, &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n\nr := 1\n",
		}})
		if errs := errorsOf(check(m, nil), agentconfig.SeverityError); len(errs) == 0 {
			t.Fatal("a package outside the manifest roots must be rejected")
		}
	})
}

// TestCheck_DeniedBuiltinNeverExecutes is the D17/§8 regression: a denied builtin reachable
// from authored Rego (or called by a vendor test) must never run on the agent host, not even
// while the revision is being rejected.
func TestCheck_DeniedBuiltinNeverExecutes(t *testing.T) {
	var hits atomic.Int32
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer probe.Close()

	vendor := map[string]string{
		"lib/net.rego": "package ccf_libs.net\n\nfetch(u) := http.send({\"method\": \"GET\", \"url\": u})\n",
		"banner.rego":  vendorBanner,
	}

	t.Run("authored test through a vendor helper is rejected before tests run", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Modules: map[string]string{
			"x_test.rego": "package compliance_framework.x_test\n\nimport data.ccf_libs.net\n\ntest_x if { net.fetch(\"" + probe.URL + "/exfil?d=secret\") }\n",
		}})
		errs := errorsOf(check(m, nil), agentconfig.SeverityError)
		if len(errs) == 0 || !strings.Contains(PolicyErrors(errs).Error(), "forbidden builtin http.send") {
			t.Fatalf("expected the forbidden builtin error, got %+v", errs)
		}
	})

	t.Run("vendor test calling http.send is sandboxed", func(t *testing.T) {
		withTest := map[string]string{
			"lib/net_test.rego": "package ccf_libs.net_test\n\nimport data.ccf_libs.net\n\ntest_fetch if { net.fetch(\"" + probe.URL + "/vendor\") }\n\ntest_direct if { http.send({\"method\": \"GET\", \"url\": \"" + probe.URL + "/direct\"}) }\n",
		}
		for k, v := range vendor {
			withTest[k] = v
		}
		m := materialize(t, withTest, &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n\nr := 1\n",
		}})
		res := check(m, nil)
		if errs := errorsOf(res, agentconfig.SeverityError); len(errs) != 0 {
			t.Fatalf("vendor tests must only warn, got errors %+v", errs)
		}
		if warns := errorsOf(res, agentconfig.SeverityWarning); len(warns) != 2 {
			t.Fatalf("expected both vendor tests to fail as warnings, got %+v", res)
		}
	})

	if n := hits.Load(); n != 0 {
		t.Fatalf("the probe server received %d request(s); a denied builtin executed during Check", n)
	}
}

func TestCheck_Tests(t *testing.T) {
	vendor := map[string]string{
		"banner.rego":      vendorBanner,
		"banner_test.rego": "package compliance_framework.banner_test\n\nimport data.compliance_framework.banner\n\ntest_fails if { count(banner.violation) == 42 with input as {} }\n",
	}
	t.Run("failing vendor test warns", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Modules: map[string]string{"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n\nr := 1\n"}})
		res := check(m, nil)
		if len(errorsOf(res, agentconfig.SeverityError)) != 0 || len(errorsOf(res, agentconfig.SeverityWarning)) != 1 {
			t.Fatalf("expected exactly one warning, got %+v", res)
		}
	})
	t.Run("failing authored test rejects", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Delete: []string{"banner_test.rego"}, Modules: map[string]string{
			"x_test.rego": "package compliance_framework.x_test\n\ntest_bad if { 1 == 2 }\n",
		}})
		if errs := errorsOf(check(m, nil), agentconfig.SeverityError); len(errs) != 1 || errs[0].Path != "x_test.rego" || errs[0].Row == 0 {
			t.Fatalf("expected one authored test error with a location, got %+v", errs)
		}
	})
	t.Run("policy_data is visible", func(t *testing.T) {
		m := materialize(t, map[string]string{}, &agentconfig.PolicyBundle{
			Modules: map[string]string{"x_test.rego": "package compliance_framework.x_test\n\ntest_data if { data.limits.max == 5; data.limits.keep == true }\n"},
			Data:    map[string]any{"limits": map[string]any{"keep": true}},
		})
		if res := check(m, map[string]any{"limits": map[string]any{"max": 5}}); len(res) != 0 {
			t.Fatalf("expected the test to see bundle data and policy_data, got %+v", res)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		old := TestTimeout
		TestTimeout = time.Second
		t.Cleanup(func() { TestTimeout = old })
		m := materialize(t, map[string]string{}, &agentconfig.PolicyBundle{Modules: map[string]string{
			"x_test.rego": "package compliance_framework.x_test\n\ntest_slow if { count([x | some x in numbers.range(1, 100000000)]) > 0 }\n",
		}})
		start := time.Now()
		res := errorsOf(check(m, nil), agentconfig.SeverityError)
		if len(res) == 0 || time.Since(start) > 20*time.Second {
			t.Fatalf("expected a timeout error within bounds, got %+v after %s", res, time.Since(start))
		}
	})
}

// TestMergePolicyDataParity checks that the test store sees the same data a plugin evaluates.
func TestMergePolicyDataParity(t *testing.T) {
	m := materialize(t, map[string]string{}, &agentconfig.PolicyBundle{
		Modules: map[string]string{"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n\nr := 1\n"},
		Data:    map[string]any{"a": map[string]any{"x": 1, "y": 2}, "list": []any{1}},
	})
	policyData := map[string]any{"a": map[string]any{"y": 3, "z": map[string]any{"q": true}}, "list": []any{2}, "b": 5}
	query, err := policyeval.NewFromBundlePath(m.Dir, policyData, policyeval.Options{}).PrepareForEval(context.Background(), rego.Query("x = data"))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := query.Eval(context.Background())
	if err != nil || len(rs) != 1 {
		t.Fatalf("eval: %v %v", rs, err)
	}
	got, _ := json.Marshal(rs[0].Bindings["x"].(map[string]any))
	var gotMap map[string]any
	_ = json.Unmarshal(got, &gotMap)
	delete(gotMap, "compliance_framework")

	var bundleData map[string]any
	_ = json.Unmarshal([]byte(readFile(t, m.Dir, "data.json")), &bundleData)
	want, _ := json.Marshal(mergePolicyData(bundleData, policyData))
	var wantMap map[string]any
	_ = json.Unmarshal(want, &wantMap)
	if !reflect.DeepEqual(gotMap, wantMap) {
		t.Fatalf("parity: policyeval sees %v, mergePolicyData gives %v", gotMap, wantMap)
	}
}

func TestGC_KeepsActiveAndNewest(t *testing.T) {
	root := t.TempDir()
	var dirs []string
	for i := 0; i < 8; i++ {
		d := filepath.Join(root, "ssh", strings.Repeat(string(rune('a'+i)), 4))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		mod := time.Now().Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(d, mod, mod); err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, d)
	}
	if err := os.MkdirAll(filepath.Join(root, "ssh", ".tmp-abc"), 0o755); err != nil {
		t.Fatal(err)
	}
	keep := map[string]struct{}{dirs[0]: {}} // the oldest is active
	if err := GC(root, keep, 5); err != nil {
		t.Fatal(err)
	}
	for i, d := range dirs {
		_, err := os.Stat(d)
		exists := err == nil
		want := i == 0 || i >= 3 // active + the 5 newest (3..7)
		if exists != want {
			t.Fatalf("dir %d exists=%v want %v", i, exists, want)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "ssh", ".tmp-abc")); !os.IsNotExist(err) {
		t.Fatal("abandoned temp dirs must be removed")
	}
}
