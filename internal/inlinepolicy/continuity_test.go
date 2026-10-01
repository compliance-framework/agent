package inlinepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// R82: inherited and overridden modules of an inline bundle keep the vendor's evidence
// streams without any policy_id written by the user, and plugins receive the bundle at a
// relative, local-source-style path.

const (
	// r82Vendor is where the agent extracts the vendor OCI bundle: relative to the working
	// directory, ending in the artifact's policies directory.
	r82Vendor = ".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0/policies"
	// r82Links is where the agent links inline bundles (cmd's inlineLinksDir).
	r82Links = ".compliance-framework/policies/inline"
)

var r82VendorFiles = map[string]string{
	"ssh/require_key_based_ssh.rego":      "package compliance_framework.require_key_based_ssh\n\nimport rego.v1\n\ntitle := \"Key based SSH\"\n\nviolation contains {\"id\": \"k\"} if input.password\n",
	"ssh/deny_root_login.rego":            "package compliance_framework.deny_root_login\n\nimport rego.v1\n\ntitle := \"No root login\"\n\nviolation contains {\"id\": \"r\"} if input.root\n",
	"banner.rego":                         "package compliance_framework.banner\n\nimport rego.v1\n\ntitle := \"Banner\"\n\nviolation contains {\"id\": \"b\"} if not input.banner\n",
	"ssh/require_key_based_ssh_test.rego": "package compliance_framework.require_key_based_ssh_test\n\nimport rego.v1\n\ntest_ok if true\n",
	"lib/helpers.rego":                    "package ccf_libs.helpers\n\nimport rego.v1\n\nyes := true\n",
}

// r82Setup writes the vendor tree at r82Vendor in a new working directory and returns the
// layout the agent uses there (the store under the state directory, given absolute as
// CCF_STATE_DIR would) and a resolver that returns the literal relative vendor path.
func r82Setup(t *testing.T) (Layout, Resolver) {
	t.Helper()
	wd := t.TempDir()
	t.Chdir(wd)
	skipWithoutSymlinks(t, wd)
	for p, src := range r82VendorFiles {
		dst := filepath.Join(r82Vendor, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
		require.NoError(t, os.WriteFile(dst, []byte(src), 0o644))
	}
	l := Layout{Store: filepath.Join(wd, ".compliance-framework", "state", "local-dev", "inline"), Links: r82Links}
	return l, func(_ context.Context, source string) (string, error) {
		require.Equal(t, "ghcr.io/compliance-framework/plugin-local-ssh-policies:v0.2.0", source)
		return r82Vendor, nil
	}
}

// r82Materialize materializes and activates bundle "custom" with modules over the vendor.
func r82Materialize(t *testing.T, l Layout, resolve Resolver, modules map[string]string) *Materialized {
	t.Helper()
	m, err := Materialize(context.Background(), l, "custom", &agentconfig.PolicyBundle{
		Extends: strptr("ghcr.io/compliance-framework/plugin-local-ssh-policies:v0.2.0"),
		Modules: modules,
	}, resolve)
	require.NoError(t, err)
	require.NoError(t, Activate(l, "custom", m.Dir))
	return m
}

type r82Evidence struct {
	uuid   string
	labels map[string]string
}

// r82Run evaluates policyPath the way the ssh plugin does (labels with _policy_path) and
// returns each package's evidence.
func r82Run(t *testing.T, policyPath string) map[string]r82Evidence {
	t.Helper()
	labels := map[string]string{"type": "ssh", "hostname": "kube-prod-worker-4", "_policy_path": policyPath}
	evidence, err := policyManager.NewPolicyProcessor(hclog.NewNullLogger(), labels, nil, nil, nil, nil, nil, nil).
		GenerateResults(context.Background(), policyPath, map[string]any{"password": true})
	require.NoError(t, err)
	out := map[string]r82Evidence{}
	for _, e := range evidence {
		out[e.Labels["_policy"]] = r82Evidence{e.UUID, e.Labels}
	}
	require.NotEmpty(t, out, "no evidence at %s", policyPath)
	return out
}

// TestR82_InheritedModulesKeepTheVendorStream: adding a module to a bundle that extends the
// vendor leaves every inherited module on its vendor evidence UUID.
func TestR82_InheritedModulesKeepTheVendorStream(t *testing.T) {
	l, resolve := r82Setup(t)
	m := r82Materialize(t, l, resolve, map[string]string{
		"custom/new.rego": "package compliance_framework.custom_new\n\nimport rego.v1\n\ntitle := \"New\"\n\nviolation contains {\"id\": \"n\"} if input.password\n",
	})

	// (5) The plugin path is the relative, local-source-style path, and the tree loads.
	assert.Equal(t, ".compliance-framework/policies/inline/custom/policies", filepath.ToSlash(m.Path))
	got := r82Run(t, m.Path)
	assert.Len(t, got, 4, "the three vendor policies and the new one")

	vendor := r82Run(t, r82Vendor)
	for _, pkg := range []string{"compliance_framework.require_key_based_ssh", "compliance_framework.deny_root_login", "compliance_framework.banner"} {
		require.Contains(t, got, pkg)
		assert.Equal(t, vendor[pkg].uuid, got[pkg].uuid, "%s must continue the vendor stream", pkg)
		assert.Equal(t, m.Path, got[pkg].labels["_policy_path"], "the evidence keeps the real _policy_path label")
		assert.NotEmpty(t, got[pkg].labels["_policy_id"], "the evidence records the continuity policy_id")
	}
	assert.Equal(t, r82Vendor+"/ssh/require_key_based_ssh.rego", got["compliance_framework.require_key_based_ssh"].labels["_policy_id"])

	newEvidence := got["compliance_framework.custom_new"]
	assert.NotContains(t, newEvidence.labels, "_policy_id", "a new module keeps a path-based stream")
	assert.Equal(t, m.Path, newEvidence.labels["_policy_path"])

	assert.Equal(t, map[string]string{
		"banner.rego":                    r82Vendor + "/banner.rego",
		"ssh/deny_root_login.rego":       r82Vendor + "/ssh/deny_root_login.rego",
		"ssh/require_key_based_ssh.rego": r82Vendor + "/ssh/require_key_based_ssh.rego",
	}, m.Continued, "only inherited compliance_framework modules, not tests, libraries or new modules")
	assert.Empty(t, OverrideStreams(m))

	// The report inventories the tree as written, so its files match the digest and the
	// uploaded artifact; the vendor files stay in the extends report.
	for _, f := range m.Files {
		if f.Path == "banner.rego" {
			assert.NotEqual(t, sha(r82VendorFiles["banner.rego"]), f.SHA256)
		}
	}
	for _, f := range m.Extends.Files {
		if f.Path == "banner.rego" {
			assert.Equal(t, sha(r82VendorFiles["banner.rego"]), f.SHA256)
		}
	}

	// Another revision of the bundle keeps the path and the streams (R67).
	again := r82Materialize(t, l, resolve, map[string]string{
		"custom/new.rego": "package compliance_framework.custom_new\n\nimport rego.v1\n\ntitle := \"New v2\"\n\nviolation contains {\"id\": \"n\"} if input.password\n",
	})
	assert.NotEqual(t, m.Dir, again.Dir)
	assert.Equal(t, m.Path, again.Path)
	after := r82Run(t, again.Path)
	for pkg, e := range got {
		assert.Equal(t, e.uuid, after[pkg].uuid, "%s keeps its stream across revisions", pkg)
	}
}

// TestR82_Overrides: an override at the vendor path with the vendor's package continues the
// vendor stream without a policy_id; one with another package starts a new stream and is
// warned about; an explicit policy_id always wins.
func TestR82_Overrides(t *testing.T) {
	const path = "ssh/require_key_based_ssh.rego"
	const pkg = "compliance_framework.require_key_based_ssh"
	t.Run("same package, no policy_id", func(t *testing.T) {
		l, resolve := r82Setup(t)
		src := "package compliance_framework.require_key_based_ssh\n\nimport rego.v1\n\ntitle := \"Key based SSH (tuned)\"\n\nviolation contains {\"id\": \"k2\"} if input.password\n"
		m := r82Materialize(t, l, resolve, map[string]string{path: src})
		assert.Equal(t, withContinuity(src, r82Vendor, path), readFile(t, m.Dir, path))
		assert.Equal(t, r82Run(t, r82Vendor)[pkg].uuid, r82Run(t, m.Path)[pkg].uuid)
		assert.Empty(t, OverrideStreams(m), "no policy-stream-forked warning for a module that now continues")
	})
	t.Run("changed package", func(t *testing.T) {
		l, resolve := r82Setup(t)
		src := "package compliance_framework.require_key_based_ssh_v2\n\nimport rego.v1\n\ntitle := \"Key based SSH v2\"\n\nviolation contains {\"id\": \"k2\"} if input.password\n"
		m := r82Materialize(t, l, resolve, map[string]string{path: src})
		assert.Equal(t, src, readFile(t, m.Dir, path), "a changed package gets no continuity policy_id")
		got := r82Run(t, m.Path)
		require.Contains(t, got, pkg+"_v2")
		vendorUUID := r82Run(t, r82Vendor)[pkg].uuid
		assert.NotEqual(t, vendorUUID, got[pkg+"_v2"].uuid)
		warnings := OverrideStreams(m)
		require.Len(t, warnings, 1)
		assert.Equal(t, agentconfig.PolicyCodePolicyPackageChanged, warnings[0].Code)
		assert.Equal(t, path, warnings[0].Path)
	})
	t.Run("explicit policy_id", func(t *testing.T) {
		l, resolve := r82Setup(t)
		src := "package compliance_framework.require_key_based_ssh\n\nimport rego.v1\n\npolicy_id := \"ssh-key-based\"\n\ntitle := \"Key based SSH\"\n\nviolation contains {\"id\": \"k\"} if input.password\n"
		m := r82Materialize(t, l, resolve, map[string]string{path: src})
		assert.Equal(t, src, readFile(t, m.Dir, path), "an explicit policy_id is left alone")
		assert.NotContains(t, m.Continued, path)
		got := r82Run(t, m.Path)[pkg]
		assert.Equal(t, "ssh-key-based", got.labels["_policy_id"])
		assert.NotEqual(t, r82Run(t, r82Vendor)[pkg].uuid, got.uuid)
		warnings := OverrideStreams(m)
		require.Len(t, warnings, 1, "an explicit policy_id that forks the stream is still warned about")
		assert.Equal(t, CodePolicyStreamForked, warnings[0].Code)
	})
}

// TestR82_MultiModulePackageIsSkipped: a package with two non-test modules in the bundle
// gets no policy_id (it would name one file for both), and a warning says so.
func TestR82_MultiModulePackageIsSkipped(t *testing.T) {
	l, resolve := r82Setup(t)
	extra := "package compliance_framework.banner\n\nimport rego.v1\n\nbanner_text := \"hello\"\n"
	m := r82Materialize(t, l, resolve, map[string]string{"banner_extra.rego": extra})
	assert.Equal(t, r82VendorFiles["banner.rego"], readFile(t, m.Dir, "banner.rego"))
	assert.Equal(t, extra, readFile(t, m.Dir, "banner_extra.rego"))
	assert.NotContains(t, m.Continued, "banner.rego")
	assert.Contains(t, m.Continued, "ssh/deny_root_login.rego", "other packages still continue")

	var skipped []agentconfig.PolicyError
	for _, w := range m.Warnings {
		if w.Code == CodeContinuityPolicyIDSkipped {
			skipped = append(skipped, w)
		}
	}
	require.Len(t, skipped, 1)
	assert.Equal(t, "banner.rego", skipped[0].Path)
	assert.Equal(t, agentconfig.SeverityWarning, skipped[0].Severity)
	assert.Contains(t, skipped[0].Message, "banner.rego, banner_extra.rego")
	assert.Contains(t, skipped[0].Message, `policy_id := "`+r82Vendor+`/banner.rego"`)

	vendorUUID := r82Run(t, r82Vendor)["compliance_framework.banner"].uuid
	assert.NotContains(t, r82UUIDs(t, m.Path, "compliance_framework.banner"), vendorUUID)

	// A policy_id the user declares in one module of the package continues the stream of
	// the vendor file (plugins evaluate each module of a package, so banner.rego's
	// evidence is the vendor's and banner_extra.rego's has its own).
	fixed := extra + "\npolicy_id := \"" + r82Vendor + "/banner.rego\"\n"
	m = r82Materialize(t, l, resolve, map[string]string{"banner_extra.rego": fixed})
	for _, w := range m.Warnings {
		assert.NotEqual(t, CodeContinuityPolicyIDSkipped, w.Code)
	}
	assert.Contains(t, r82UUIDs(t, m.Path, "compliance_framework.banner"), vendorUUID)
}

// r82UUIDs returns the evidence UUIDs of package pkg at policyPath (one per module).
func r82UUIDs(t *testing.T, policyPath, pkg string) []string {
	t.Helper()
	labels := map[string]string{"type": "ssh", "hostname": "kube-prod-worker-4", "_policy_path": policyPath}
	evidence, err := policyManager.NewPolicyProcessor(hclog.NewNullLogger(), labels, nil, nil, nil, nil, nil, nil).
		GenerateResults(context.Background(), policyPath, map[string]any{"password": true})
	require.NoError(t, err)
	var out []string
	for _, e := range evidence {
		if e.Labels["_policy"] == pkg {
			out = append(out, e.UUID)
		}
	}
	return out
}

// TestR82_RegoV0Module: a vendor module only Rego v0 parses still gets the policy_id
// (detected with the v0 parser; the appended rule is valid in both).
func TestR82_RegoV0Module(t *testing.T) {
	const v0 = "package compliance_framework.legacy\n\ntitle = \"Legacy\"\n\nviolation[{\"id\": \"l\"}] {\n  input.password\n}\n"
	_, err := ast.ParseModuleWithOpts("legacy.rego", v0, ast.ParserOptions{RegoVersion: ast.RegoV1})
	require.Error(t, err, "the fixture must be v0-only")

	m := &Materialized{Name: "b", Extends: &agentconfig.PolicyBundleExtendsReport{Source: "s"}, ExtendsDir: "vendor", Continued: map[string]string{}}
	tree := map[string][]byte{"legacy.rego": []byte(v0)}
	assert.Empty(t, continueVendorStreams(m, tree, map[string][]byte{"legacy.rego": []byte(v0)}))
	assert.Equal(t, withContinuity(v0, "vendor", "legacy.rego"), string(tree["legacy.rego"]))
	assert.Equal(t, map[string]string{"legacy.rego": "vendor/legacy.rego"}, m.Continued)
}

// TestR82_MigratesTheR67Layout: the R67 layout (<store>/<name>/current -> <hex> with the tree
// in bundle/) is replaced: Materialize writes the new layout and GC removes the old trees
// and the current link.
func TestR82_MigratesTheR67Layout(t *testing.T) {
	root := t.TempDir()
	skipWithoutSymlinks(t, root)
	l := testLayout(root)
	old := filepath.Join(l.Store, "ssh", "0123abcd")
	require.NoError(t, os.MkdirAll(filepath.Join(old, "bundle"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(old, "bundle", "x.rego"), []byte("package compliance_framework.x\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(old, treeMarker), nil, 0o644))
	require.NoError(t, os.Symlink("0123abcd", filepath.Join(l.Store, "ssh", legacyCurrentLink)))

	m, err := Materialize(context.Background(), l, "ssh", &agentconfig.PolicyBundle{Modules: map[string]string{"x.rego": "package compliance_framework.x\n\ntitle := \"x\"\n"}}, nil)
	require.NoError(t, err)
	require.NoError(t, Activate(l, "ssh", m.Dir))
	require.NoError(t, GC(l, map[string]struct{}{m.Dir: {}}, 5))

	_, err = os.Stat(old)
	assert.True(t, os.IsNotExist(err), "the R67 tree must be collected")
	_, err = os.Lstat(filepath.Join(l.Store, "ssh", legacyCurrentLink))
	assert.True(t, os.IsNotExist(err), "the R67 current link must be removed")
	assert.Equal(t, "package compliance_framework.x\n\ntitle := \"x\"\n", readFile(t, m.Path, "x.rego"))
	info, err := os.Lstat(filepath.Join(l.Links, "ssh"))
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "the bundle's link is a symlink")
	info, err = os.Lstat(filepath.Join(l.Links, "ssh", "policies"))
	require.NoError(t, err)
	assert.True(t, info.IsDir(), "policies/ is a real directory inside the linked tree")
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
