package policy_manager

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/rego"
	"slices"
	"strings"
)

type PolicyManager struct {
	logger        hclog.Logger
	loaderOptions []func(r *rego.Rego)
}

func New(ctx context.Context, logger hclog.Logger, bundlePath string) *PolicyManager {
	return &PolicyManager{
		logger: logger,
		loaderOptions: []func(r *rego.Rego){
			rego.LoadBundle(bundlePath),
		},
	}
}

func (pm *PolicyManager) Execute(ctx context.Context, pluginNamespace string, input map[string]interface{}) ([]Result, error) {
	var output []Result

	pm.logger.Debug("Executing policy", "input", input)
	regoArgs := []func(r *rego.Rego){
		rego.Query("data.compliance_framework"),
		rego.Package(fmt.Sprintf("compliance_framework.%s", pluginNamespace)),
	}
	regoArgs = append(regoArgs, pm.loaderOptions...)
	r := rego.New(regoArgs...)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	for _, module := range query.Modules() {
		// Exclude any test files for this compilation
		if strings.HasSuffix(module.Package.Location.File, "_test.rego") {
			continue
		}

		result := Result{
			Policy: Policy{
				File:        module.Package.Location.File,
				Package:     Package(module.Package.Path.String()),
				Annotations: module.Annotations,
			},
			AdditionalVariables: map[string]interface{}{},
			Violations:          nil,
			Activities:          nil,
			Risks:               nil,
		}

		regoArgs := []func(r *rego.Rego){
			rego.Query(module.Package.Path.String()),
			rego.Package(module.Package.Path.String()),
			rego.Input(input),
		}
		regoArgs = append(regoArgs, pm.loaderOptions...)

		subQuery := rego.New(regoArgs...)

		evaluation, err := subQuery.Eval(ctx)
		if err != nil {
			return nil, err
		}

		for _, eval := range evaluation {
			for _, expression := range eval.Expressions {
				moduleOutputs := expression.Value.(map[string]interface{})

				for key, value := range moduleOutputs {
					if !slices.Contains([]string{"violation", "activities", "risks"}, key) {
						result.AdditionalVariables[key] = value
					}
				}

				for _, tester := range moduleOutputs["violation"].([]interface{}) {
					var violation Violation

					contents, err := json.Marshal(tester.(map[string]interface{}))
					if err != nil {
						return nil, err
					}

					err = json.Unmarshal(contents, &violation)
					if err != nil {
						return nil, err
					}

					result.Violations = append(result.Violations, violation)
				}

				for _, tester := range moduleOutputs["activities"].([]interface{}) {
					var activity Activity

					contents, err := json.Marshal(tester.(map[string]interface{}))
					if err != nil {
						return nil, err
					}

					err = json.Unmarshal(contents, &activity)
					if err != nil {
						return nil, err
					}

					result.Activities = append(result.Activities, activity)
				}

				for _, tester := range moduleOutputs["risks"].([]interface{}) {
					var risk Risk
					contents, err := json.Marshal(tester.(map[string]interface{}))
					if err != nil {
						return nil, err
					}

					err = json.Unmarshal(contents, &risk)
					if err != nil {
						return nil, err
					}

					result.Risks = append(result.Risks, risk)
				}
			}
		}
		output = append(output, result)
	}

	//compiler
	return output, nil
}
