package policy_manager

import (
	"context"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/rego"
)

func buildPolicyManager(regoContents []byte) *PolicyManager {
	return &PolicyManager{
		logger: hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Debug,
			JSONFormat: true,
		}),
		loaderOptions: []func(r *rego.Rego){
			rego.ParsedBundle("test", &bundle.Bundle{
				Modules: []bundle.ModuleFile{
					{
						Path:   "test.rego",
						Parsed: ast.MustParseModule(string(regoContents[:])),
						Raw:    []byte(regoContents),
					},
				},
				Manifest: bundle.Manifest{Revision: "test", Roots: &[]string{"/"}},
			}),
		},
	}
}

func TestPolicyManager(t *testing.T) {
	t.Run("Policy Manager understands bundles", func(t *testing.T) {
		ctx := context.Background()

		var data = map[string]interface{}{}

		policyManager := New(ctx, hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Debug,
			JSONFormat: true,
		}), "testdata/")

		results, err := policyManager.Execute(ctx, "local_ssh", data)

		assert.NoError(t, err)
		assert.Equal(t, len(results), 1)

		result := results[0]

		assert.Equal(t, len(result.Tasks), 1)
		assert.Equal(t, "Task1", result.Tasks[0].Title)
		assert.Equal(t, "Do the thing", result.Tasks[0].Description)
		assert.Equal(t, 2, len(result.Tasks[0].Activities))
		assert.Equal(t, Activity{
			Title:       "Activity1",
			Description: "Do the first thing",
			Type:        "test",
			Steps: []Step{
				{
					Title:       "First Step",
					Description: "First Step in full form",
				},
				{
					Title:       "Second Step",
					Description: "Second Step in full form",
				},
			},
			Tools: []string{
				"Tool 1",
				"Tool 2",
			},
		}, result.Tasks[0].Activities[0])
		assert.Equal(t, Activity{
			Title:       "Activity2",
			Description: "Do the next thing",
			Type:        "test",
			Steps: []Step{
				{
					Title:       "Activity 2 First Step",
					Description: "First Step in full form",
				},
				{
					Title:       "Activity 2 Second Step",
					Description: "Second Step in full form",
				},
			},
			Tools: []string{
				"Tool 1",
				"Tool 2",
			},
		}, result.Tasks[0].Activities[1])

		assert.Equal(t, 2, len(result.Risks))
		assert.Equal(t, Risk{
			Title:       "Risk 1",
			Description: "Risky business",
			Statement:   "We could be at risk",
			Links: []Link{
				{
					Text: "stuff",
					URL:  "https://attack.mitre.org/techniques/T123/",
				},
			},
		}, result.Risks[0])
		assert.Equal(t, Risk{
			Title:       "Risk 2",
			Description: "Even riskier business",
			Statement:   "You should be worried",
			Links: []Link{
				{
					Text: "stuff",
					URL:  "https://attack.mitre.org/techniques/T124/",
				},
			},
		}, result.Risks[1])

		assert.Equal(t, 0, len(result.Violations))
	})

	t.Run("Policy Manager handles violations", func(t *testing.T) {
		ctx := context.Background()

		regoContents, err := os.ReadFile("testdata/test_policy.rego")
		assert.NoError(t, err)

		var data map[string]interface{} = make(map[string]interface{})
		data["violated"] = []string{"yes"}

		results, err := buildPolicyManager(regoContents).Execute(ctx, "test", data)

		assert.NoError(t, err)
		assert.Equal(t, 1, len(results))

		result := results[0]

		assert.Equal(t, 1, len(result.Violations))
		assert.Equal(t, Violation{
			Title:       "Violation 1",
			Description: "You have been violated.",
			Remarks:     "Migrate to not being violated",
			Controls: []string{
				"AC-1",
				"AC-2",
			},
		}, result.Violations[0])
	})

	// Removed as we are unmarshalling a map, and any extra keys will just be ignored
	//t.Run("Policy Manager handles errors in specification", func(t *testing.T) {
	//	ctx := context.Background()
	//
	//	regoContents := []byte(`# METADATA
	//# title: Stuff
	//# description: Verify we're doing stuff
	//
	//package compliance_framework.local_ssh.deny_password_auth
	//
	//import future.keywords.in
	//
	//tasks := [
	//   {
	//       "title": "Task1",
	//       "description": "Do the thing",
	//       "activities": [
	//           {
	//               "title": "Activity1",
	//               "description": "Do the first thing",
	//               "nonsense": "test",
	//           }
	//       ]
	//   }
	//]`)
	//
	//	var data map[string]interface{} = make(map[string]interface{})
	//
	//	_, err := buildPolicyManager(regoContents).Execute(ctx, "test", data)
	//
	//	assert.EqualError(t, err, "Activity entry contains unexpected key: nonsense")
	//})
}
