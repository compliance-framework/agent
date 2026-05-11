package policy_manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
)

func buildPolicyManager(regoContents []byte) *PolicyManager {
	return buildPolicyManagerWithModules(map[string][]byte{
		"test.rego": regoContents,
	})
}

func buildPolicyManagerWithModules(modules map[string][]byte) *PolicyManager {
	bundleModules := make([]bundle.ModuleFile, 0, len(modules))
	for path, regoContents := range modules {
		bundleModules = append(bundleModules, bundle.ModuleFile{
			Path:   path,
			Parsed: ast.MustParseModule(string(regoContents[:])),
			Raw:    []byte(regoContents),
		})
	}

	return &PolicyManager{
		logger: hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Debug,
			JSONFormat: true,
		}),
		loaderOptions: []func(r *rego.Rego){
			rego.ParsedBundle("test", &bundle.Bundle{
				Modules:  bundleModules,
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

	t.Run("Policy Manager evaluates risk templates with helper refs without evaluating unrelated rules", func(t *testing.T) {
		ctx := context.Background()

		regoContents := []byte(`package compliance_framework.static_risk_templates

template_name := "password_auth_enabled"
template_title := "Password authentication enabled"
template_statement := "SSH password authentication is enabled."
template_likelihood := "medium"
template_impact := "high"
template_violation_ids := ["ssh.password_auth_enabled"]
template_threat := {
	"system": "ATT&CK",
	"external_id": "T1110",
	"title": "Brute Force",
	"url": "https://attack.mitre.org/techniques/T1110/"
}
template_remediation := {
	"title": "Disable password authentication",
	"description": "Use SSH keys instead of passwords.",
	"tasks": [{"title": "Set PasswordAuthentication to no"}]
}

risk_templates := [{
	"name": template_name,
	"title": template_title,
	"statement": template_statement,
	"likelihood_hint": template_likelihood,
	"impact_hint": template_impact,
	"violation_ids": template_violation_ids,
	"threat_refs": [template_threat],
	"remediation": template_remediation,
}]

violation[{"title": "this should not be evaluated"}] if {
	_ := 1 / 0
}
`)

		templates, err := buildPolicyManager(regoContents).GetRiskTemplates(ctx)

		assert.NoError(t, err)
		policyTemplates := templates["compliance_framework.static_risk_templates"]
		if assert.Len(t, policyTemplates, 1) {
			template := policyTemplates[0]
			assert.NotEmpty(t, template.UUID)
			assert.Equal(t, "compliance_framework.static_risk_templates", template.PolicyPackage)
			assert.Equal(t, "password_auth_enabled", template.Name)
			assert.Equal(t, "Password authentication enabled", template.Title)
			assert.Equal(t, "SSH password authentication is enabled.", template.Statement)
			assert.Equal(t, "medium", template.LikelihoodHint)
			assert.Equal(t, "high", template.ImpactHint)
			assert.Equal(t, []string{"ssh.password_auth_enabled"}, template.ViolationIds)
			if assert.Len(t, template.ThreatRefs, 1) {
				assert.Equal(t, "ATT&CK", template.ThreatRefs[0].System)
				assert.Equal(t, "T1110", template.ThreatRefs[0].ExternalID)
			}
			if assert.NotNil(t, template.Remediation) {
				assert.Equal(t, "Disable password authentication", template.Remediation.Title)
				if assert.Len(t, template.Remediation.Tasks, 1) {
					assert.Equal(t, "Set PasswordAuthentication to no", template.Remediation.Tasks[0].Title)
				}
			}
		}
	})

	t.Run("Policy Manager propagates template-capable risk template fields", func(t *testing.T) {
		ctx := context.Background()

		regoContents := []byte(`package compliance_framework.templateable_risk_templates

risk_templates := [{
	"name": "templated_password_auth_enabled",
	"title": "Password authentication enabled on {{ .subject }}",
	"statement": "SSH password authentication is enabled on {{ .subject }}.",
	"likelihood_hint": "{{ .likelihood }}",
	"impact_hint": "{{ .impact }}",
	"dedupe_label_keys": ["cluster", "hostname"],
	"label_schema": [
		{
			"key": "cluster",
			"description": "Cluster name"
		},
		{
			"key": "hostname",
			"description": "Host name"
		}
	]
}]
`)

		templates, err := buildPolicyManager(regoContents).GetRiskTemplates(ctx)

		assert.NoError(t, err)
		policyTemplates := templates["compliance_framework.templateable_risk_templates"]
		if assert.Len(t, policyTemplates, 1) {
			template := policyTemplates[0]
			assert.Equal(t, "templated_password_auth_enabled", template.Name)
			assert.Equal(t, "Password authentication enabled on {{ .subject }}", template.Title)
			assert.Equal(t, "SSH password authentication is enabled on {{ .subject }}.", template.Statement)
			assert.Equal(t, "{{ .likelihood }}", template.LikelihoodHint)
			assert.Equal(t, "{{ .impact }}", template.ImpactHint)
			assert.Equal(t, []string{"cluster", "hostname"}, template.DedupeLabelKeys)
			if assert.Len(t, template.LabelSchema, 2) {
				assert.Equal(t, "cluster", template.LabelSchema[0].Key)
				assert.Equal(t, "Cluster name", template.LabelSchema[0].Description)
				assert.Equal(t, "hostname", template.LabelSchema[1].Key)
				assert.Equal(t, "Host name", template.LabelSchema[1].Description)
			}
		}
	})

	t.Run("Policy Manager skips modules without static risk templates", func(t *testing.T) {
		ctx := context.Background()

		modules := map[string][]byte{
			"no_templates.rego": []byte(`package compliance_framework.no_templates

violation[{"title": "no template here"}] if {
	input.violated
}
`),
			"with_templates.rego": []byte(`package compliance_framework.with_templates

risk_templates := [{
	"name": "password_auth_enabled",
	"title": "Password authentication enabled",
	"statement": "SSH password authentication is enabled.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["ssh.password_auth_enabled"]
}]
`),
		}

		templates, err := buildPolicyManagerWithModules(modules).GetRiskTemplates(ctx)

		assert.NoError(t, err)
		if assert.Len(t, templates, 2) {
			assert.Empty(t, templates["compliance_framework.no_templates"])
			policyTemplates := templates["compliance_framework.with_templates"]
			if assert.Len(t, policyTemplates, 1) {
				assert.Equal(t, "password_auth_enabled", policyTemplates[0].Name)
				assert.Equal(t, "compliance_framework.with_templates", policyTemplates[0].PolicyPackage)
				assert.Nil(t, policyTemplates[0].Remediation)
			}
		}
	})
}

func TestPolicyProcessorNewEvidenceRejectsMissingTitle(t *testing.T) {
	processor := &PolicyProcessor{
		labels: map[string]string{
			"_plugin": "test-plugin",
		},
	}

	evidence, err := processor.newEvidence(Result{
		Policy: Policy{
			File:    "test.rego",
			Package: Package("data.compliance_framework.missing_title"),
		},
		EvalOutput: &EvalOutput{},
	}, nil)

	assert.Nil(t, evidence)
	assert.EqualError(t, err, "evidence title is required")
}

func TestPolicyProcessorGenerateResultsRejectsEvidenceWithoutTitle(t *testing.T) {
	ctx := context.Background()
	policyDir := t.TempDir()
	regoContents := []byte(`package compliance_framework.missing_title

description := "Evidence was generated without a title"
`)

	err := os.WriteFile(filepath.Join(policyDir, "missing_title.rego"), regoContents, 0o644)
	assert.NoError(t, err)

	processor := NewPolicyProcessor(
		hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Debug,
			JSONFormat: true,
		}),
		map[string]string{
			"_plugin": "test-plugin",
		},
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	evidences, err := processor.GenerateResults(ctx, policyDir, map[string]interface{}{})

	assert.Empty(t, evidences)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "evidence title is required")
	}
}

func TestPolicyManagerExecuteWithSkip(t *testing.T) {
	ctx := context.Background()

	// Test case 1: skip=true should set Skip field to true
	regoContentsSkip := []byte(`package compliance_framework.skip_test

import future.keywords.in

title := "This should be skipped"
description := "This evidence should not be produced"
skip := true

violation[{
    "title": "Test violation",
}] if {
	false
}
`)

	results, err := buildPolicyManager(regoContentsSkip).Execute(ctx, map[string]interface{}{})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.True(t, results[0].Skip, "Skip field should be true when policy sets skip=true")

	// Test case 2: skip=false should set Skip field to false
	regoContentsNoSkip := []byte(`package compliance_framework.no_skip_test

import future.keywords.in

title := "This should not be skipped"
description := "This evidence should be produced"
skip := false

violation[{
    "title": "Test violation",
}] if {
	false
}
`)

	results, err = buildPolicyManager(regoContentsNoSkip).Execute(ctx, map[string]interface{}{})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.False(t, results[0].Skip, "Skip field should be false when policy sets skip=false")

	// Test case 3: skip not set should default to false
	regoContentsNoSkipField := []byte(`package compliance_framework.no_skip_field

import future.keywords.in

title := "This should not be skipped"
description := "This evidence should be produced"

violation[{
    "title": "Test violation",
}] if {
	false
}
`)

	results, err = buildPolicyManager(regoContentsNoSkipField).Execute(ctx, map[string]interface{}{})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.False(t, results[0].Skip, "Skip field should default to false when not set")
}

func TestPolicyProcessorSkipEvidence(t *testing.T) {
	ctx := context.Background()

	// Test case 1: skip=true should skip evidence production
	policyDirSkip := t.TempDir()
	regoContentsSkip := []byte(`package compliance_framework.skip_test

import future.keywords.in

title := "This should be skipped"
description := "This evidence should not be produced"
skip := true

violation[{
    "title": "Test violation",
}] if {
	false
}
`)

	err := os.WriteFile(filepath.Join(policyDirSkip, "skip_test.rego"), regoContentsSkip, 0o644)
	assert.NoError(t, err)

	processorSkip := NewPolicyProcessor(
		hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Debug,
			JSONFormat: true,
		}),
		map[string]string{
			"_plugin": "test-plugin",
		},
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	evidences, err := processorSkip.GenerateResults(ctx, policyDirSkip, map[string]interface{}{})

	assert.NoError(t, err)
	assert.Empty(t, evidences, "No evidence should be produced when skip=true")
}

func TestPolicyProcessorSkipEvidenceBypassesTitleValidation(t *testing.T) {
	ctx := context.Background()
	policyDir := t.TempDir()

	// Test case: skip=true without title should not error
	regoContentsSkipNoTitle := []byte(`package compliance_framework.skip_no_title

description := "This should be skipped without title"
skip := true
`)

	err := os.WriteFile(filepath.Join(policyDir, "skip_no_title.rego"), regoContentsSkipNoTitle, 0o644)
	assert.NoError(t, err)

	processor := NewPolicyProcessor(
		hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Debug,
			JSONFormat: true,
		}),
		map[string]string{
			"_plugin": "test-plugin",
		},
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	evidences, err := processor.GenerateResults(ctx, policyDir, map[string]interface{}{})

	assert.NoError(t, err)
	assert.Empty(t, evidences, "No evidence should be produced when skip=true, even without title")
}
