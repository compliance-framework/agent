package policy_manager

import (
	"context"
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
			Tasks:               nil,
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
					violation, err := mapToViolation(tester.(map[string]interface{}))
					if err != nil {
						return nil, err
					}

					result.Violations = append(result.Violations, violation)
				}

				for _, tester := range moduleOutputs["tasks"].([]interface{}) {
					task, err := mapToTask(tester.(map[string]interface{}))
					if err != nil {
						return nil, err
					}

					result.Tasks = append(result.Tasks, task)
				}

				for _, tester := range moduleOutputs["risks"].([]interface{}) {
					risk, err := mapToRisk(tester.(map[string]interface{}))
					if err != nil {
						return nil, err
					}

					result.Risks = append(result.Risks, risk)
				// 	var risk Risk
				// 	contents, err := json.Marshal(tester.(map[string]interface{}))
				// 	if err != nil {
				// 		return nil, err
				// 	}

				// 	err = json.Unmarshal(contents, &risk)
				// 	if err != nil {
				// 		return nil, err
				// 	}

				// 	result.Risks = append(result.Risks, risk)
				}
			}
		}
		output = append(output, result)
	}

	//compiler
	return output, nil
}

func mapToViolation(data map[string]interface{}) (Violation, error) {
	title := data["title"].(string)
	description := data["description"].(string)
	remarks := data["remarks"].(string)
	controls := data["control-implementations"].([]interface{})
	var controlsList []string
	for _, control := range controls {
		controlsList = append(controlsList, control.(string))
	}

	return Violation {
		Title: title,
		Description: description,
		Remarks: remarks,
		Controls: controlsList,
	}, nil
}

func mapToTask(data map[string]interface{}) (Task, error) {
	title := data["title"].(string)
	description := data["description"].(string)
	activities := data["activities"].([]interface{})
	var activitiesList []Activity
	for _, activity := range activities {
		activityMap := activity.(map[string]interface{})
		var stepsList []Step
		for _, step := range activityMap["steps"].([]interface{}) {
			stepsList = append(stepsList, Step{
				Title: step.(string),
			})
		}
		var toolsList []string
		for _, tool := range activityMap["tools"].([]interface{}) {
			toolsList = append(toolsList, tool.(string))
		}
		activitiesList = append(activitiesList, Activity{
			Title: activityMap["title"].(string),
			Description: activityMap["description"].(string),
			Type: activityMap["type"].(string),
			Steps: stepsList,
			Tools: toolsList,
		})
	}

	return Task {
		Title: title,
		Description: description,
		Activities: activitiesList,
	}, nil
}

func mapToRisk(data map[string]interface{}) (Risk, error) {
	title := data["title"].(string)
	description := data["description"].(string)
	statement := data["statement"].(string)
	links := data["links"].([]interface{})
	var linksList []Link
	for _, link := range links {
		linkMap := link.(map[string]interface{})
		linksList = append(linksList, Link{
			Text: linkMap["text"].(string),
			URL: linkMap["href"].(string),
		})
	}

	return Risk {
		Title: title,
		Description: description,
		Statement: statement,
		Links: linksList,
	}, nil
}
