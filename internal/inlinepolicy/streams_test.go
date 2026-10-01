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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Evidence streams of an inline bundle that extends a vendor bundle: shadowed, plugins
// receive the vendor's path and every module that keeps its package keeps its stream; not
// shadowed, plugins receive the bundle's own path and its modules start path-based streams
// (R88), which OverrideStreams warns about.

const (
	// streamsVendor is where the agent extracts the vendor OCI bundle: relative to the
	// working directory, ending in the artifact's policies directory.
	streamsVendor = ".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0/policies"
	// streamsLinks is where the agent links inline bundles (cmd's inlineLinksDir).
	streamsLinks  = ".compliance-framework/policies/_inline"
	streamsSource = "ghcr.io/compliance-framework/plugin-local-ssh-policies:v0.2.0"
)

var streamsVendorFiles = map[string]string{
	"ssh/require_key_based_ssh.rego":      "package compliance_framework.require_key_based_ssh\n\nimport rego.v1\n\ntitle := \"Key based SSH\"\n\nviolation contains {\"id\": \"k\"} if input.password\n",
	"ssh/deny_root_login.rego":            "package compliance_framework.deny_root_login\n\nimport rego.v1\n\npolicy_id := \"ssh-deny-root-login\"\n\ntitle := \"No root login\"\n\nviolation contains {\"id\": \"r\"} if input.root\n",
	"banner.rego":                         "package compliance_framework.banner\n\nimport rego.v1\n\ntitle := \"Banner\"\n\nviolation contains {\"id\": \"b\"} if not input.banner\n",
	"ssh/require_key_based_ssh_test.rego": "package compliance_framework.require_key_based_ssh_test\n\nimport rego.v1\n\ntest_ok if true\n",
	"lib/helpers.rego":                    "package ccf_libs.helpers\n\nimport rego.v1\n\nyes := true\n",
}

// streamsSetup writes the vendor tree at streamsVendor in a new working directory and
// returns the layout the agent uses there (the store under the state directory, absolute as
// CCF_STATE_DIR would give it) and a resolver that returns the literal relative vendor path.
func streamsSetup(t *testing.T) (Layout, Resolver) {
	t.Helper()
	wd := t.TempDir()
	t.Chdir(wd)
	skipWithoutSymlinks(t, wd)
	for p, src := range streamsVendorFiles {
		dst := filepath.Join(streamsVendor, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
		require.NoError(t, os.WriteFile(dst, []byte(src), 0o644))
	}
	l := Layout{Store: filepath.Join(wd, ".compliance-framework", "state", "local-dev", "inline"), Links: streamsLinks}
	return l, func(_ context.Context, source string) (string, error) {
		require.Equal(t, streamsSource, source)
		return streamsVendor, nil
	}
}

// streamsMaterialize materializes and activates bundle "custom" with modules over the vendor.
func streamsMaterialize(t *testing.T, l Layout, resolve Resolver, modules map[string]string, opts ...Options) *Materialized {
	t.Helper()
	m, err := Materialize(context.Background(), l, "custom", &agentconfig.PolicyBundle{
		Extends: strptr(streamsSource),
		Modules: modules,
	}, resolve, opts...)
	require.NoError(t, err)
	require.NoError(t, Activate(l, "custom", m.Dir))
	return m
}

type streamsEvidence struct {
	uuid   string
	labels map[string]string
}

// streamsRun evaluates policyPath the way the ssh plugin does (labels with _policy_path)
// from working directory dir and returns each package's evidence.
func streamsRun(t *testing.T, dir, policyPath string) map[string]streamsEvidence {
	t.Helper()
	back, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(back) }()
	labels := map[string]string{"type": "ssh", "hostname": "kube-prod-worker-4", "_policy_path": policyPath}
	evidence, err := policyManager.NewPolicyProcessor(hclog.NewNullLogger(), labels, nil, nil, nil, nil, nil, nil).
		GenerateResults(context.Background(), policyPath, map[string]any{"password": true})
	require.NoError(t, err)
	out := map[string]streamsEvidence{}
	for _, e := range evidence {
		out[e.Labels["_policy"]] = streamsEvidence{e.UUID, e.Labels}
	}
	require.NotEmpty(t, out, "no evidence at %s", policyPath)
	return out
}

// shadowView links the shadowed vendor path to m's tree in a new directory, as the agent's
// per-plugin view does (internal/policyview), and returns that directory.
func shadowView(t *testing.T, m *Materialized) string {
	t.Helper()
	view := t.TempDir()
	link := filepath.Join(view, filepath.Dir(streamsVendor))
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
	target, err := filepath.Abs(filepath.Dir(m.Dir))
	require.NoError(t, err)
	require.NoError(t, os.Symlink(target, link))
	return view
}

// TestStreams_UnshadowedBundleStartsPathStreams: a bundle plugins receive at its own path
// keeps the vendor files as they are (no policy_id is added), so its inherited modules start
// path-based streams under the relative _inline path, which is warned about once; a module
// whose vendor package declares a policy_id keeps the vendor stream. Another revision keeps
// the path and the streams (R67).
func TestStreams_UnshadowedBundleStartsPathStreams(t *testing.T) {
	l, resolve := streamsSetup(t)
	m := streamsMaterialize(t, l, resolve, map[string]string{
		"custom/new.rego": "package compliance_framework.custom_new\n\nimport rego.v1\n\ntitle := \"New\"\n\nviolation contains {\"id\": \"n\"} if input.password\n",
	})
	assert.False(t, m.Shadowed)
	assert.Equal(t, streamsLinks+"/custom/policies", filepath.ToSlash(m.Path))
	for p, src := range streamsVendorFiles {
		assert.Equal(t, src, readFile(t, m.Dir, p), "%s must keep the vendor bytes", p)
	}

	wd, err := os.Getwd()
	require.NoError(t, err)
	got := streamsRun(t, wd, m.Path)
	assert.Len(t, got, 4, "the three vendor policies and the new one")
	vendor := streamsRun(t, wd, streamsVendor)
	for _, pkg := range []string{"compliance_framework.require_key_based_ssh", "compliance_framework.banner"} {
		require.Contains(t, got, pkg)
		assert.NotEqual(t, vendor[pkg].uuid, got[pkg].uuid, "%s starts a path-based stream", pkg)
		assert.Equal(t, m.Path, got[pkg].labels["_policy_path"])
		assert.NotContains(t, got[pkg].labels, "_policy_id")
	}
	assert.Equal(t, vendor["compliance_framework.deny_root_login"].uuid, got["compliance_framework.deny_root_login"].uuid,
		"the vendor's own policy_id keeps the stream")

	warnings := OverrideStreams(m)
	require.Len(t, warnings, 1, "one warning for the inherited modules: %+v", warnings)
	assert.Equal(t, CodePolicyStreamForked, warnings[0].Code)
	assert.Equal(t, agentconfig.SeverityWarning, warnings[0].Severity)
	assert.Empty(t, warnings[0].Path)
	assert.Contains(t, warnings[0].Message, "inherited modules (banner.rego, ssh/require_key_based_ssh.rego)")

	// The report inventories the tree as written; the vendor files stay in the extends report.
	assert.Equal(t, sha(streamsVendorFiles["banner.rego"]), fileSHA(m.Extends.Files, "banner.rego"))
	assert.Equal(t, sha(streamsVendorFiles["banner.rego"]), fileSHA(m.Files, "banner.rego"))

	again := streamsMaterialize(t, l, resolve, map[string]string{
		"custom/new.rego": "package compliance_framework.custom_new\n\nimport rego.v1\n\ntitle := \"New v2\"\n\nviolation contains {\"id\": \"n\"} if input.password\n",
	})
	assert.NotEqual(t, m.Dir, again.Dir)
	assert.Equal(t, m.Path, again.Path)
	after := streamsRun(t, wd, again.Path)
	for pkg, e := range got {
		assert.Equal(t, e.uuid, after[pkg].uuid, "%s keeps its stream across revisions", pkg)
	}
}

// TestStreams_Shadowed: with Options.Shadow and a shadowable extends path, plugins receive
// the extends path itself, and in a view every inherited module and every override that
// keeps its package keeps the vendor stream, with no warning. An absolute extends path
// ignores the option.
func TestStreams_Shadowed(t *testing.T) {
	l, resolve := streamsSetup(t)
	const path = "ssh/require_key_based_ssh.rego"
	const pkg = "compliance_framework.require_key_based_ssh"
	m := streamsMaterialize(t, l, resolve, map[string]string{
		path:              "package compliance_framework.require_key_based_ssh\n\nimport rego.v1\n\ntitle := \"Key based SSH (tuned)\"\n\nviolation contains {\"id\": \"k2\"} if input.password\n",
		"custom/new.rego": "package compliance_framework.custom_new\n\nimport rego.v1\n\ntitle := \"New\"\n\nviolation[{\"id\": \"n\"}] if input.password\n",
	}, Options{Shadow: true})
	assert.True(t, m.Shadowed)
	assert.Equal(t, streamsVendor, m.Path, "plugins receive the vendor's path string")
	assert.Empty(t, OverrideStreams(m))

	wd, err := os.Getwd()
	require.NoError(t, err)
	vendor := streamsRun(t, wd, streamsVendor)
	got := streamsRun(t, shadowView(t, m), streamsVendor)
	for _, p := range []string{pkg, "compliance_framework.banner", "compliance_framework.deny_root_login"} {
		assert.Equal(t, vendor[p].uuid, got[p].uuid, "%s keeps the vendor stream", p)
	}
	assert.Contains(t, got, "compliance_framework.custom_new")

	abs, err := filepath.Abs(streamsVendor)
	require.NoError(t, err)
	m, err = Materialize(context.Background(), l, "custom", &agentconfig.PolicyBundle{Extends: strptr(streamsSource)},
		func(context.Context, string) (string, error) { return abs, nil }, Options{Shadow: true})
	require.NoError(t, err)
	assert.False(t, m.Shadowed, "an absolute extends path cannot be shadowed")
	assert.Equal(t, streamsLinks+"/custom/policies", filepath.ToSlash(m.Path))
}

// TestStreams_Overrides: the R75 warnings about overrides, shadowed or not.
func TestStreams_Overrides(t *testing.T) {
	const keyBased = "ssh/require_key_based_ssh.rego"
	const rootLogin = "ssh/deny_root_login.rego"
	codes := func(warnings []agentconfig.PolicyError) map[string]string {
		out := map[string]string{}
		for _, w := range warnings {
			if w.Path != "" {
				out[w.Path] = w.Code
			}
		}
		return out
	}
	for _, tc := range []struct {
		name    string
		shadow  bool
		modules map[string]string
		want    map[string]string // path -> code
		hint    string            // a policy_id the warning suggests
	}{
		{
			name:    "shadowed, same package",
			shadow:  true,
			modules: map[string]string{keyBased: "package compliance_framework.require_key_based_ssh\n\nimport rego.v1\n\ntitle := \"tuned\"\n"},
			want:    map[string]string{},
		},
		{
			name:    "shadowed, changed package",
			shadow:  true,
			modules: map[string]string{keyBased: "package compliance_framework.require_key_based_ssh_v2\n\nimport rego.v1\n\ntitle := \"v2\"\n"},
			want:    map[string]string{keyBased: agentconfig.PolicyCodePolicyPackageChanged},
		},
		{
			name:    "shadowed, own policy_id",
			shadow:  true,
			modules: map[string]string{keyBased: "package compliance_framework.require_key_based_ssh\n\nimport rego.v1\n\npolicy_id := \"ssh-key-based\"\n\ntitle := \"tuned\"\n"},
			want:    map[string]string{keyBased: CodePolicyStreamForked},
		},
		{
			name:    "shadowed, vendor policy_id dropped",
			shadow:  true,
			modules: map[string]string{rootLogin: "package compliance_framework.deny_root_login\n\nimport rego.v1\n\ntitle := \"tuned\"\n"},
			want:    map[string]string{rootLogin: CodePolicyStreamForked},
			hint:    `policy_id := "ssh-deny-root-login"`,
		},
		{
			name:    "not shadowed, same package",
			modules: map[string]string{keyBased: "package compliance_framework.require_key_based_ssh\n\nimport rego.v1\n\ntitle := \"tuned\"\n"},
			want:    map[string]string{keyBased: CodePolicyStreamForked},
		},
		{
			name:    "not shadowed, vendor policy_id kept",
			modules: map[string]string{rootLogin: "package compliance_framework.deny_root_login\n\nimport rego.v1\n\npolicy_id := \"ssh-deny-root-login\"\n\ntitle := \"tuned\"\n"},
			want:    map[string]string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, resolve := streamsSetup(t)
			m := streamsMaterialize(t, l, resolve, tc.modules, Options{Shadow: tc.shadow})
			require.Equal(t, tc.shadow, m.Shadowed)
			warnings := OverrideStreams(m)
			assert.Equal(t, tc.want, codes(warnings))
			for _, w := range warnings {
				assert.Equal(t, agentconfig.SeverityWarning, w.Severity)
				if tc.hint != "" && w.Path != "" {
					assert.Contains(t, w.Message, tc.hint)
				}
			}
		})
	}
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func fileSHA(files []agentconfig.PolicyFileReport, p string) string {
	for _, f := range files {
		if f.Path == p {
			return f.SHA256
		}
	}
	return ""
}
