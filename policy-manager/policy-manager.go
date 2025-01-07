package policy_manager

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/rego"
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

				violations, err := mapToViolations(moduleOutputs)
				if err != nil {
					return nil, err
				}

				result.Violations = violations

				tasks, err := mapToTasks(moduleOutputs)
				if err != nil {
					return nil, err
				}

				result.Tasks = tasks

				risks, err := mapToRisks(moduleOutputs)
				if err != nil {
					return nil, err
				}

				result.Risks = risks
			}
		}
		output = append(output, result)
	}

	//compiler
	return output, nil
}

func mapToViolations(data map[string]interface{}) ([]Violation, error) {
	violations := []Violation{}

	violationsEntry, ok := data["violation"]
	if !ok {
		return violations, nil
	}

	violationsList, ok := violationsEntry.([]interface{})
	if !ok {
		return nil, errors.New("Violations not a list as expected")
	}

	for _, violationEntry := range violationsList {
		violation, ok := violationEntry.(map[string]interface{})
		if !ok {
			return nil, errors.New("Violation entry not an object as expected")
		}

		for key := range violation {
			if !slices.Contains([]string{"title", "description", "remarks", "control-implementations"}, key) {
				return nil, fmt.Errorf("Violation entry contains unexpected key: %s", key)
			}
		}

		title, ok := violation["title"].(string)
		if !ok {
			return nil, errors.New("Violation title not a string as expected")
		}

		description, ok := violation["description"].(string)
		if !ok {
			return nil, errors.New("Violation description not a string as expected")
		}

		remarks, ok := violation["remarks"].(string)
		if !ok {
			return nil, errors.New("Violation remarks not a string as expected")
		}

		controls, ok := violation["control-implementations"].([]interface{})
		if !ok {
			return nil, errors.New("Violation controls not a list as expected")
		}

		var controlsList []string
		for _, controlEntry := range controls {
			control, ok := controlEntry.(string)
			if !ok {
				return nil, errors.New("Violation control entry not a string as expected")
			}
			controlsList = append(controlsList, control)
		}

		violations = append(violations, Violation {
			Title: title,
			Description: description,
			Remarks: remarks,
			Controls: controlsList,
		})
	}

	return violations, nil
}

func mapToTasks(data map[string]interface{}) ([]Task, error) {
	tasks := []Task{}

	tasksEntry, ok := data["tasks"]
	if !ok {
		return tasks, nil
	}

	tasksList, ok := tasksEntry.([]interface{})
	if !ok {
		return nil, errors.New("Tasks not a list as expected")
	}

	for _, taskEntry := range tasksList {
		task, ok := taskEntry.(map[string]interface{})
		if !ok {
			return nil, errors.New("Task entry not an object as expected")
		}

		for key := range task {
			if !slices.Contains([]string{"title", "description", "activities"}, key) {
				return nil, fmt.Errorf("Task entry contains unexpected key: %s", key)
			}
		}

		title, ok := task["title"].(string)
		if !ok {
			return nil, errors.New("Task title not a string as expected")
		}

		description, ok := task["description"].(string)
		if !ok {
			return nil, errors.New("Task description not a string as expected")
		}

		activities, ok := task["activities"].([]interface{})
		if !ok {
			return nil, errors.New("Task activities not a list as expected")
		}

		var activitiesList []Activity

		for _, activityEntry := range activities {
			activity, ok := activityEntry.(map[string]interface{})

			for key := range activity {
				if !slices.Contains([]string{"title", "description", "type", "tools", "steps"}, key) {
					return nil, fmt.Errorf("Activity entry contains unexpected key: %s", key)
				}
			}

			if !ok {
				return nil, errors.New("Activity entry not an object as expected")
			}

			title, ok := activity["title"].(string)
			if !ok {
				return nil, errors.New("Activity title not a string as expected")
			}

			description, ok := activity["description"].(string)
			if !ok {
				return nil, errors.New("Activity description not a string as expected")
			}

			type_, ok := activity["type"].(string)
			if !ok {
				return nil, errors.New("Activity type not a string as expected")
			}

			tools, ok := activity["tools"].([]interface{})
			if !ok {
				return nil, errors.New("Activity tools not a list as expected")
			}

			var toolsList []string
			for _, toolEntry := range tools {
				tool, ok := toolEntry.(string)
				if !ok {
					return nil, errors.New("Tool entry not a string as expected")
				}
				toolsList = append(toolsList, tool)
			}

			steps, ok := activity["steps"].([]interface{})

			var stepsList []Step
			for _, stepEntry := range steps {
				step, ok := stepEntry.(string)
				if !ok {
					return nil, errors.New("Step entry not a string as expected")
				}
				stepsList = append(stepsList, Step{
					Title: step,
				})
			}

			activitiesList = append(activitiesList, Activity {
				Title: title,
				Description: description,
				Type: type_,
				Steps: stepsList,
				Tools: toolsList,
			})
		}

		tasks = append(tasks, Task {
			Title: title,
			Description: description,
			Activities: activitiesList,
		})
	}

	return tasks, nil
}

func mapToRisks(data map[string]interface{}) ([]Risk, error) {
	risks := []Risk{}

	risksEntry, ok := data["risks"]
	if !ok {
		return risks, nil
	}

	risksList, ok := risksEntry.([]interface{})
	if !ok {
		return nil, errors.New("Risks not a list as expected")
	}

	for _, riskEntry := range risksList {
		risk, ok := riskEntry.(map[string]interface{})
		if !ok {
			return nil, errors.New("Risk entry not an object as expected")
		}

		for key := range risk {
			if !slices.Contains([]string{"title", "description", "statement", "links"}, key) {
				return nil, fmt.Errorf("Risk entry contains unexpected key: %s", key)
			}
		}

		title, ok := risk["title"].(string)
		if !ok {
			return nil, errors.New("Risk title not a string as expected")
		}

		description, ok := risk["description"].(string)
		if !ok {
			return nil, errors.New("Risk description not a string as expected")
		}

		statement, ok := risk["statement"].(string)
		if !ok {
			return nil, errors.New("Risk statement not a string as expected")
		}

		links, ok := risk["links"].([]interface{})
		if !ok {
			return nil, errors.New("Risk links not a list as expected")
		}

		var linksList []Link
		for _, linkEntry := range links {
			link, ok := linkEntry.(map[string]interface{})
			if !ok {
				return nil, errors.New("Link entry not an object as expected")
			}

			for key := range link {
				if !slices.Contains([]string{"text", "href"}, key) {
					return nil, fmt.Errorf("Link entry contains unexpected key: %s", key)
				}
			}

			text, ok := link["text"].(string)
			if !ok {
				return nil, errors.New("Link text not a string as expected")
			}

			url, ok := link["href"].(string)
			if !ok {
				return nil, errors.New("Link href not a string as expected")
			}

			linksList = append(linksList, Link{
				Text: text,
				URL: url,
			})
		}

		risks = append(risks, Risk {
			Title: title,
			Description: description,
			Statement: statement,
			Links: linksList,
		})
	}

	return risks, nil
}
