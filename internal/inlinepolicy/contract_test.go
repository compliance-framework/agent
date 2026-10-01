package inlinepolicy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/policyeval"
)

// The e2e repro of §13.1: the UI's Override replaced the vendor module with a skeleton, so the
// vendor test in the same package no longer compiles.
const (
	sshVendorModule = `package compliance_framework.ssh_deny_password_auth

import rego.v1

title := "SSH password authentication is disabled"

violation contains {"id": "password-auth", "title": "Password authentication is enabled"} if {
	input.passwordauthentication == "yes"
}
`
	sshVendorTest = `package compliance_framework.ssh_deny_password_auth

import rego.v1

test_password_auth_denied if {
	count(violation) == 1 with input as {"passwordauthentication": "yes"}
}
`
	sshOverrideSkeleton = "package compliance_framework.ssh_deny_password_auth\n\nimport rego.v1\n"
)

func TestCheck_OverrideBreaksVendorTest_R65(t *testing.T) {
	vendor := map[string]string{
		"ssh/ssh_deny_password_auth.rego":      sshVendorModule,
		"ssh/ssh_deny_password_auth_test.rego": sshVendorTest,
	}

	m := materialize(t, vendor, &agentconfig.PolicyBundle{
		Extends: strptr("ghcr.io/vendor/policies:v1"),
		Modules: map[string]string{"ssh/ssh_deny_password_auth.rego": sshOverrideSkeleton},
	})
	errs := errorsOf(check(m, nil), agentconfig.SeverityError)
	if len(errs) == 0 {
		t.Fatal("a vendor test that no longer compiles must reject the revision")
	}
	var found bool
	for _, e := range errs {
		if e.Path == "ssh/ssh_deny_password_auth_test.rego" && strings.Contains(e.Message, "violation") &&
			strings.Contains(e.Message, "vendor test references rules removed by the override of `ssh/ssh_deny_password_auth.rego`; keep the rule or add `delete: [ssh/ssh_deny_password_auth_test.rego]`") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the compile error in the vendor test with the override hint, got %+v", errs)
	}

	// Deleting the vendor test makes the bundle compile; the skeleton still has no title, so
	// its package would record no evidence: that is an error for an authored package.
	m = materialize(t, vendor, &agentconfig.PolicyBundle{
		Extends: strptr("ghcr.io/vendor/policies:v1"),
		Delete:  []string{"ssh/ssh_deny_password_auth_test.rego"},
		Modules: map[string]string{"ssh/ssh_deny_password_auth.rego": sshOverrideSkeleton},
	})
	errs = errorsOf(check(m, nil), agentconfig.SeverityError)
	if len(errs) != 1 || errs[0].Code != policyeval.IssueMissingTitle || errs[0].Path != "ssh/ssh_deny_password_auth.rego" {
		t.Fatalf("expected one missing-title error on the override, got %+v", errs)
	}

	// No hint on a compile error in an authored file.
	m = materialize(t, vendor, &agentconfig.PolicyBundle{
		Extends: strptr("ghcr.io/vendor/policies:v1"),
		Modules: map[string]string{"ssh/ssh_deny_password_auth.rego": sshVendorModule + "\nbroken if { undefined_var }\n"},
	})
	for _, e := range errorsOf(check(m, nil), agentconfig.SeverityError) {
		if strings.Contains(e.Message, "hint:") {
			t.Fatalf("an authored compile error must not carry the vendor hint: %+v", e)
		}
	}
}

func codes(errs []agentconfig.PolicyError, path string) map[string]string {
	out := map[string]string{}
	for _, e := range errs {
		if e.Path == path {
			out[e.Code] = e.Severity
		}
	}
	return out
}

func TestCheck_Contract_R63(t *testing.T) {
	vendor := map[string]string{
		"banner.rego":    vendorBanner,
		"untitled.rego":  "package compliance_framework.untitled\n\nviolation contains {\"id\": \"u\"} if input.x\n",
		"badvendor.rego": "package compliance_framework.badvendor\n\ntitle := \"bad vendor\"\n\nviolation contains v if { v := \"not-an-object\" }\n",
	}
	ext := strptr("ghcr.io/vendor/policies:v1")

	t.Run("authored decode error is an error, vendor one a warning, both reported", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: ext, Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n\nviolation contains v if { v := 42 }\n",
		}})
		res := check(m, nil)
		if got := codes(res, "x.rego")[policyeval.IssueInvalidViolation]; got != agentconfig.SeverityError {
			t.Fatalf("expected an eval error on the authored package, got %+v", res)
		}
		if got := codes(res, "badvendor.rego")[policyeval.IssueInvalidViolation]; got != agentconfig.SeverityWarning {
			t.Fatalf("expected a warning on the vendor package, got %+v", res)
		}
		n := 0
		for _, e := range res {
			if e.Path == "badvendor.rego" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("the static and dynamic checks must not both report the vendor package, got %+v", res)
		}
	})

	t.Run("vendor-only problems warn once", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: ext, Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n",
		}})
		res := check(m, nil)
		if errs := errorsOf(res, agentconfig.SeverityError); len(errs) != 0 {
			t.Fatalf("vendor debt must not reject, got %+v", errs)
		}
		n := 0
		for _, e := range res {
			if e.Path == "untitled.rego" && e.Code == policyeval.IssueMissingTitle {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("expected exactly one missing-title warning for the vendor package, got %d in %+v", n, res)
		}
	})

	t.Run("an authored test does not make vendor debt an error", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: ext, Modules: map[string]string{
			"untitled_test.rego": "package compliance_framework.untitled\n\ntest_ok if { count(violation) == 1 with input as {\"x\": true} }\n",
		}})
		if errs := errorsOf(check(m, nil), agentconfig.SeverityError); len(errs) != 0 {
			t.Fatalf("vendor debt must stay a warning, got %+v", errs)
		}
	})

	t.Run("authored package without a title is rejected", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: ext, Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\nviolation contains {\"id\": \"x\"} if input.x\n",
		}})
		if got := codes(check(m, nil), "x.rego")[policyeval.IssueMissingTitle]; got != agentconfig.SeverityError {
			t.Fatalf("expected a missing-title error, got %q", got)
		}
	})

	t.Run("a title that depends on the input only warns", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: ext, Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"x\" if input.enabled\n",
		}})
		if got := codes(check(m, nil), "x.rego")[policyeval.IssueMissingTitle]; got != agentconfig.SeverityWarning {
			t.Fatalf("expected a missing-title warning, got %q", got)
		}
	})

	t.Run("an evaluation conflict on an empty input only warns", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: ext, Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n\nv := 1\n\nv := 2 if not input.y\n",
		}})
		if got := codes(check(m, nil), "x.rego")[codeEvalConflict]; got != agentconfig.SeverityWarning {
			t.Fatalf("expected an eval-conflict warning, got %q", got)
		}
	})

	t.Run("invalid risk templates of an authored package are an error", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: ext, Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n\nrisk_templates := [{\"name\": \"r\"}] if true\n",
		}})
		got := codes(check(m, nil), "x.rego")
		if got[policyeval.IssueInvalidRiskTemplate] != agentconfig.SeverityError {
			t.Fatalf("expected an invalid-risk-template error, got %v", got)
		}
	})

	t.Run("an authored module joining a vendor package duplicates its evidence", func(t *testing.T) {
		m := materialize(t, vendor, &agentconfig.PolicyBundle{Extends: ext, Modules: map[string]string{
			"banner_extra.rego": "package compliance_framework.banner\n\nremarks := \"more\"\n",
		}})
		res := check(m, nil)
		if got := codes(res, "banner_extra.rego")[policyeval.IssueDuplicatePackageModule]; got != agentconfig.SeverityWarning {
			t.Fatalf("expected a duplicate-package-module warning, got %+v", res)
		}
	})
}

// TestCheck_DryRunIsSandboxed: the dry run evaluates vendor packages too, and a denied
// builtin they call must never execute.
func TestCheck_DryRunIsSandboxed(t *testing.T) {
	var hits atomic.Int32
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer probe.Close()

	m := materialize(t, map[string]string{
		"leak.rego": "package compliance_framework.leak\n\ntitle := \"leak\"\n\nr := http.send({\"method\": \"GET\", \"url\": \"" + probe.URL + "\"})\n",
	}, &agentconfig.PolicyBundle{Extends: strptr("ghcr.io/vendor/policies:v1"), Modules: map[string]string{
		"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n",
	}})
	if errs := errorsOf(check(m, nil), agentconfig.SeverityError); len(errs) != 0 {
		t.Fatalf("unexpected errors %+v", errs)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the probe server received %d request(s) during the dry run", n)
	}
}
