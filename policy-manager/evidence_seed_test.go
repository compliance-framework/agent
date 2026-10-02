package policy_manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEvidenceSeedIsUnchanged pins the evidence UUIDs plugins in the field produce for
// several label and path combinations. Every evidence stream depends on them (path shadowing
// keeps vendor streams only because the seed is the path string): they must never change.
func TestEvidenceSeedIsUnchanged(t *testing.T) {
	const (
		// vendorPath is the policy path an OCI bundle is passed as: relative to the agent's
		// working directory, with the repository and tag.
		vendorPath = ".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0/policies"
		inlinePath = "/app/.compliance-framework/state/local-dev/inline/test/current/bundle"
	)
	sshLabels := func(policyPath string) map[string]string {
		return map[string]string{"type": "ssh", "hostname": "web-1", "_policy_path": policyPath}
	}
	cases := []struct {
		name      string
		labels    map[string]string
		file, pkg string
		want      string
	}{
		{"relative OCI path", sshLabels(vendorPath), vendorPath + "/ssh_deny_password_auth.rego", "data.compliance_framework.ssh_deny_password_auth", "cede5222-a458-4465-8134-c3751575cdd9"},
		{"absolute path, nested file", sshLabels(inlinePath), inlinePath + "/ssh/banner.rego", "data.compliance_framework.banner", "966b3869-b39b-4b2b-9257-7f475e3bb54c"},
		{"no _policy_path label", map[string]string{"_plugin": "test-plugin"}, "test.rego", "data.compliance_framework.no_policy_path", "271009cd-7758-432e-8869-84fa710b0f5a"},
		{"no labels", nil, "policies/a.rego", "data.compliance_framework.a", "9eb28e96-4f5a-416a-9623-62430b8e089f"},
		{"trailing slash", map[string]string{"type": "k8s", "_policy_path": "policies/", "cluster": "prod"}, "policies/a.rego", "data.compliance_framework.a", "98fc06e7-b1a4-4d83-a272-df4fdd75d06c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &PolicyProcessor{labels: tc.labels}
			e, err := p.newEvidence(Result{
				Policy:     Policy{File: tc.file, Package: Package(tc.pkg)},
				EvalOutput: &EvalOutput{Title: Pointer("t")},
			}, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.want, e.UUID)
		})
	}
}
