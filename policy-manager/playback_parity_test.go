package policy_manager

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const parityPolicy = `package compliance_framework.sshd_hardening

title := "sshd is hardened"
description := "Root login and password authentication are disabled, and sshd listens on the approved port."

skip_reason := "sshd is not installed" if not input.installed

violation contains {"id": "root-login-enabled", "title": "Root login is enabled"} if {
	input.sshd.PermitRootLogin == "yes"
}

violation contains {"id": "password-auth-enabled", "title": "Password authentication is enabled"} if {
	input.sshd.PasswordAuthentication == "yes"
}

violation contains {"id": "unapproved-port", "title": "sshd listens on an unapproved port"} if {
	not input.sshd.Port in data.approved_ports
}
`

// playbackStatus maps the agent's evidence for one policy onto playback's vocabulary: no
// evidence is a skip, otherwise the evidence state.
func playbackStatus(evidences []*proto.Evidence) string {
	if len(evidences) == 0 {
		return policyeval.StatusSkipped
	}
	if evidences[0].Status.State == proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED {
		return policyeval.StatusSatisfied
	}
	return policyeval.StatusNotSatisfied
}

func evidenceViolationIDs(evidences []*proto.Evidence) []string {
	ids := []string{}
	for _, evidence := range evidences {
		for _, prop := range evidence.Props {
			if prop.Name == "_violation_id" {
				ids = append(ids, prop.Value)
			}
		}
	}
	slices.Sort(ids)
	return ids
}

func playbackViolationIDs(result policyeval.EvaluateResult) []string {
	ids := []string{}
	for _, violation := range result.Violations {
		if violation.ID != nil {
			ids = append(ids, *violation.ID)
		}
	}
	slices.Sort(ids)
	return ids
}

// jsonRoundTrip decodes input the way the playback endpoint does, numbers kept exact.
func jsonRoundTrip(t *testing.T, in any) any {
	t.Helper()
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&out))
	return out
}

// TestGenerateResultsMatchesPlayback runs the same policy, input and policy data through the
// agent's GenerateResults and the playback endpoint's evaluation, and asserts they agree on
// status and violation IDs.
func TestGenerateResultsMatchesPlayback(t *testing.T) {
	policyDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "sshd_hardening.rego"), []byte(parityPolicy), 0o644))

	policyData := map[string]interface{}{"approved_ports": []interface{}{22, 2222}}

	cases := map[string]map[string]interface{}{
		"hardened": {
			"installed": true,
			"sshd":      map[string]interface{}{"PermitRootLogin": "no", "PasswordAuthentication": "no", "Port": 22},
		},
		"one violation": {
			"installed": true,
			"sshd":      map[string]interface{}{"PermitRootLogin": "yes", "PasswordAuthentication": "no", "Port": 2222},
		},
		"every violation": {
			"installed": true,
			"sshd":      map[string]interface{}{"PermitRootLogin": "yes", "PasswordAuthentication": "yes", "Port": 2200},
		},
		"skipped": {
			"installed": false,
		},
	}

	processor := NewPolicyProcessor(hclog.NewNullLogger(), map[string]string{"_plugin": "parity"}, nil, nil, nil, nil, nil, policyData)

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			evidences, err := processor.GenerateResults(ctx, policyDir, input)
			require.NoError(t, err)

			resp, err := policyeval.Evaluate(ctx, policyeval.EvaluateRequest{
				Policy: parityPolicy,
				Input:  jsonRoundTrip(t, input),
				Data:   jsonRoundTrip(t, policyData).(map[string]any),
			})
			require.NoError(t, err)
			require.Len(t, resp.Results, 1)

			assert.Equal(t, playbackStatus(evidences), resp.Results[0].Status)
			assert.Equal(t, evidenceViolationIDs(evidences), playbackViolationIDs(resp.Results[0]))
		})
	}
}
