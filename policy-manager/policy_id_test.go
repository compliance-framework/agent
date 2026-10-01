package policy_manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Policy identity (R74): a policy_id replaces the location in the evidence UUID seed, and
// without one the seed is exactly what plugins have always used.

const (
	// vendorPath is the policy path an OCI bundle is passed as: relative to the agent's
	// working directory, with the repository and tag.
	vendorPath = ".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0/policies"
	// inlinePath is the stable path an inline bundle is passed as (R67): absolute.
	inlinePath = "/app/.compliance-framework/state/local-dev/inline/test/current/bundle"
)

func evidenceUUID(t *testing.T, labels map[string]string, policyPath, file, pkg, id string) *proto.Evidence {
	t.Helper()
	p := &PolicyProcessor{labels: labels}
	e, err := p.newEvidence(Result{
		Policy:     Policy{File: file, Package: Package(pkg), ID: id},
		EvalOutput: &EvalOutput{Title: Pointer("t")},
	}, policyPath, nil)
	require.NoError(t, err)
	return e
}

func sshLabels(policyPath string) map[string]string {
	return map[string]string{"type": "ssh", "hostname": "web-1", "_policy_path": policyPath}
}

// TestEvidenceSeedWithoutPolicyIDIsUnchanged pins the UUIDs plugins produced before R74 for
// several label and path combinations: without a policy_id they must never change.
func TestEvidenceSeedWithoutPolicyIDIsUnchanged(t *testing.T) {
	cases := []struct {
		name       string
		labels     map[string]string
		policyPath string
		file, pkg  string
		want       string
	}{
		{"relative OCI path", sshLabels(vendorPath), vendorPath, vendorPath + "/ssh_deny_password_auth.rego", "data.compliance_framework.ssh_deny_password_auth", "cede5222-a458-4465-8134-c3751575cdd9"},
		{"absolute inline path, nested file", sshLabels(inlinePath), inlinePath, inlinePath + "/ssh/banner.rego", "data.compliance_framework.banner", "966b3869-b39b-4b2b-9257-7f475e3bb54c"},
		{"no _policy_path label", map[string]string{"_plugin": "test-plugin"}, "", "test.rego", "data.compliance_framework.no_policy_path", "271009cd-7758-432e-8869-84fa710b0f5a"},
		{"no labels", nil, "policies", "policies/a.rego", "data.compliance_framework.a", "9eb28e96-4f5a-416a-9623-62430b8e089f"},
		{"trailing slash", map[string]string{"type": "k8s", "_policy_path": "policies/", "cluster": "prod"}, "policies/", "policies/a.rego", "data.compliance_framework.a", "98fc06e7-b1a4-4d83-a272-df4fdd75d06c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := evidenceUUID(t, tc.labels, tc.policyPath, tc.file, tc.pkg, "")
			assert.Equal(t, tc.want, e.UUID)
			assert.NotContains(t, e.Labels, labelPolicyID)
		})
	}
}

// TestPolicyIDContinuesTheLegacyStream: an override that declares the replaced policy's
// legacy policy_file as its policy_id writes to the replaced policy's stream, wherever the
// override lives.
func TestPolicyIDContinuesTheLegacyStream(t *testing.T) {
	const pkg = "data.compliance_framework.ssh_deny_password_auth"
	cases := []struct {
		name               string
		legacyPath, file   string
		overridePath       string
		overridePathLabels string
	}{
		{"vendor OCI bundle overridden inline", vendorPath, "ssh_deny_password_auth.rego", inlinePath, inlinePath},
		{"nested file", vendorPath, "ssh/ssh_deny_password_auth.rego", inlinePath, inlinePath},
		{"inline bundle renamed", inlinePath, "ssh_deny_password_auth.rego", "/app/.compliance-framework/state/local-dev/inline/renamed/current/bundle", "/app/.compliance-framework/state/local-dev/inline/renamed/current/bundle"},
		{"OCI tag bumped", vendorPath, "ssh_deny_password_auth.rego", ".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.3.0/policies", ".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.3.0/policies"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacyFile := tc.legacyPath + "/" + tc.file
			legacy := evidenceUUID(t, sshLabels(tc.legacyPath), tc.legacyPath, legacyFile, pkg, "")
			override := evidenceUUID(t, sshLabels(tc.overridePathLabels), tc.overridePath, tc.overridePath+"/"+tc.file, pkg, legacyFile)
			assert.Equal(t, legacy.UUID, override.UUID, "the override continues the legacy stream")

			assert.Equal(t, tc.overridePathLabels, override.Labels["_policy_path"], "the evidence keeps the real _policy_path")
			assert.Equal(t, legacyFile, override.Labels[labelPolicyID])
		})
	}
}

// TestOpaquePolicyIDIsLocationIndependent: an opaque policy_id gives the same stream
// whatever the bundle is called or where it lives, and a different stream from the
// path-based one.
func TestOpaquePolicyIDIsLocationIndependent(t *testing.T) {
	const pkg = "data.compliance_framework.ssh_deny_password_auth"
	const id = "ssh-deny-password-auth"
	paths := []string{
		inlinePath,
		"/app/.compliance-framework/state/local-dev/inline/renamed/current/bundle",
		"/var/lib/ccf/state/inline/test/current/bundle",
		vendorPath,
	}
	var uuids []string
	for _, path := range paths {
		e := evidenceUUID(t, sshLabels(path), path, path+"/ssh_deny_password_auth.rego", pkg, id)
		uuids = append(uuids, e.UUID)
		assert.Equal(t, id, e.Labels[labelPolicyID])
		assert.Equal(t, path, e.Labels["_policy_path"])
	}
	for _, u := range uuids[1:] {
		assert.Equal(t, uuids[0], u)
	}
	pathBased := evidenceUUID(t, sshLabels(inlinePath), inlinePath, inlinePath+"/ssh_deny_password_auth.rego", pkg, "")
	assert.NotEqual(t, pathBased.UUID, uuids[0])

	// The package stays in the seed: a different package is a different stream.
	other := evidenceUUID(t, sshLabels(inlinePath), inlinePath, inlinePath+"/ssh_deny_password_auth.rego", "data.compliance_framework.other", id)
	assert.NotEqual(t, uuids[0], other.UUID)
}

// TestPolicyIDWithoutPolicyPathLabel: plugins that do not label _policy_path seed only the
// policy_file with the policy_id; no _policy_path key is added to their seed.
func TestPolicyIDWithoutPolicyPathLabel(t *testing.T) {
	labels := map[string]string{"_plugin": "test-plugin"}
	p := &PolicyProcessor{labels: labels}
	seed := p.evidenceSeed(Result{Policy: Policy{File: "/b/x.rego", Package: "data.compliance_framework.x", ID: "x"}}, "/b")
	assert.Equal(t, map[string]string{"type": "evidence", "policy": "compliance_framework.x", "policy_file": "x", "_plugin": "test-plugin"}, seed)
	assert.Equal(t, map[string]string{"_plugin": "test-plugin"}, labels, "the plugin's labels are not modified")

	labels = sshLabels("/b")
	p = &PolicyProcessor{labels: labels}
	seed = p.evidenceSeed(Result{Policy: Policy{File: "/b/x.rego", Package: "data.compliance_framework.x", ID: "x"}}, "/b")
	assert.Equal(t, "x", seed["_policy_path"])
	assert.Equal(t, "/b", labels["_policy_path"], "the plugin's labels are not modified")
}

// TestGenerateResultsSeedsWithThePolicyID runs real bundles the way a plugin does: a vendor
// bundle without policy_id, and an override in another directory whose policy_id is the
// vendor module's legacy path, produce the same evidence UUID. Relative paths stay relative.
func TestGenerateResultsSeedsWithThePolicyID(t *testing.T) {
	for _, relative := range []bool{false, true} {
		name := "absolute"
		if relative {
			name = "relative"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if relative {
				t.Chdir(root)
				root = "."
			}
			vendor := filepath.Join(root, "vendor", "v0.2.0", "policies")
			override := filepath.Join(root, "inline", "test", "current", "bundle")
			legacyFile := vendor + "/ssh.rego"
			writeModule(t, vendor, "ssh.rego", `package compliance_framework.ssh

import rego.v1

title := "ssh"

violation contains {"id": "v"} if input.bad
`)
			writeModule(t, override, "ssh.rego", `package compliance_framework.ssh

import rego.v1

policy_id := "`+legacyFile+`"

title := "ssh (override)"

violation contains {"id": "v"} if input.bad
`)

			generate := func(policyPath string) *proto.Evidence {
				t.Helper()
				processor := NewPolicyProcessor(hclog.NewNullLogger(), sshLabels(policyPath), nil, nil, nil, nil, nil, nil)
				evidence, err := processor.GenerateResults(context.Background(), policyPath, map[string]any{"bad": true})
				require.NoError(t, err)
				require.Len(t, evidence, 1)
				return evidence[0]
			}
			legacy, overridden := generate(vendor), generate(override)
			assert.Equal(t, legacy.UUID, overridden.UUID, "the override continues the vendor stream")
			assert.NotContains(t, legacy.Labels, labelPolicyID)
			assert.Equal(t, legacyFile, overridden.Labels[labelPolicyID])
			assert.Equal(t, override, overridden.Labels["_policy_path"])
		})
	}
}

func writeModule(t *testing.T, dir, name, src string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644))
}
