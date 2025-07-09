package policy_manager

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
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
		}), "testdata/001/")

		results, err := policyManager.Execute(ctx, data)

		assert.NoError(t, err)
		assert.Equal(t, len(results), 1)

		result := results[0]
		assert.Equal(t, 0, len(result.Violations))
	})

	t.Run("Policy Manager handles violations", func(t *testing.T) {
		ctx := context.Background()

		regoContents, err := os.ReadFile("testdata/001/test_policy.rego")
		assert.NoError(t, err)

		var data map[string]interface{} = make(map[string]interface{})
		data["violated"] = []string{"yes"}

		results, err := buildPolicyManager(regoContents).Execute(ctx, data)

		assert.NoError(t, err)
		assert.Equal(t, 1, len(results))

		result := results[0]

		assert.Equal(t, 1, len(result.Violations))
		assert.Equal(t, Violation{
			Title:       Pointer("Violation 1"),
			Description: Pointer("You have been violated."),
			Remarks:     Pointer("Migrate to not being violated"),
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
