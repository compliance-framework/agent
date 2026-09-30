package policy_manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const twoPackagePolicy = `package compliance_framework.root_login

title := "Root login is disabled"

violation contains {"id": "root-login-enabled"} if input.PermitRootLogin == "yes"
`

const secondPackagePolicy = `package compliance_framework.password_auth

title := "Password authentication is disabled"

violation contains {"id": "password-auth-enabled"} if input.PasswordAuthentication == "yes"
`

func writeTwoPolicies(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root_login.rego"), []byte(twoPackagePolicy), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "password_auth.rego"), []byte(secondPackagePolicy), 0o644))
	return dir
}

func TestGenerateResultsRecordsThePolicyEvaluation(t *testing.T) {
	policyDir := writeTwoPolicies(t)
	input := map[string]interface{}{"PermitRootLogin": "yes", "PasswordAuthentication": "no"}
	policyData := map[string]interface{}{"allowed_users": []interface{}{"deploy"}}

	processor := NewPolicyProcessor(hclog.NewNullLogger(), nil, nil, nil, nil, nil, nil, policyData)
	evidences, err := processor.GenerateResults(context.Background(), policyDir, input)
	require.NoError(t, err)
	require.Len(t, evidences, 2)

	for _, evidence := range evidences {
		evaluation := evidence.GetPolicyEvaluation()
		require.NotNil(t, evaluation, evidence.Title)
		assert.Equal(t, policyDir, evaluation.PolicyPath)
		assert.JSONEq(t, `{"PermitRootLogin":"yes","PasswordAuthentication":"no"}`, string(evaluation.Input))
		assert.JSONEq(t, `{"allowed_users":["deploy"]}`, string(evaluation.PolicyData))
	}
	assert.Same(t, evidences[0].PolicyEvaluation, evidences[1].PolicyEvaluation,
		"evidence from one evaluation shares one record, so the agent uploads it once")
}

func TestGenerateResultsWithoutPolicyData(t *testing.T) {
	processor := NewPolicyProcessor(hclog.NewNullLogger(), nil, nil, nil, nil, nil, nil, nil)
	evidences, err := processor.GenerateResults(context.Background(), writeTwoPolicies(t), map[string]interface{}{"PermitRootLogin": "no"})
	require.NoError(t, err)
	require.NotEmpty(t, evidences)
	assert.Empty(t, evidences[0].GetPolicyEvaluation().GetPolicyData())
}

func TestGenerateResultsRejectsInputThatIsNotJSON(t *testing.T) {
	processor := NewPolicyProcessor(hclog.NewNullLogger(), nil, nil, nil, nil, nil, nil, nil)
	evidences, err := processor.GenerateResults(context.Background(), writeTwoPolicies(t), map[string]interface{}{"f": func() {}})
	assert.Error(t, err)
	assert.Empty(t, evidences)
}
