package policy_manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/go-viper/mapstructure/v2"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/rego"
	"google.golang.org/protobuf/types/known/timestamppb"
	"slices"
	"strings"
	"time"
)

type EvalOutput struct {
	Title               *string   `mapstructure:"title,omitempty"`
	Description         *string   `mapstructure:"description,omitempty"`
	Remarks             *string   `mapstructure:"remarks,omitempty"`
	Risks               []Risk    `mapstructure:"risks"`
	Tasks               []Task    `mapstructure:"tasks"`
	Controls            []Control `mapstructure:"controls"`
	Violations          []Violation
	AdditionalVariables map[string]interface{}
}

type PolicyManager struct {
	logger        hclog.Logger
	loaderOptions []func(r *rego.Rego)
}

func New(ctx context.Context, logger hclog.Logger, policyPath string) *PolicyManager {
	return &PolicyManager{
		logger: logger,
		loaderOptions: []func(r *rego.Rego){
			rego.LoadBundle(policyPath),
		},
	}
}

func (pm *PolicyManager) Execute(ctx context.Context, input interface{}) ([]Result, error) {
	var output []Result

	pm.logger.Trace("Executing policy", "input", input)
	regoArgs := []func(r *rego.Rego){
		rego.Query("data.compliance_framework"),
		rego.Package("compliance_framework"),
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
				violations := make([]Violation, 0)

				val, ok := moduleOutputs["violation"]
				// If the key exists
				if ok {
					// Do something
					for violation, _ := range val.(map[string]interface{}) {
						viol := &Violation{}
						err := json.Unmarshal([]byte(violation), viol)
						if err != nil {
							return nil, err
						}
						violations = append(violations, *viol)
					}
				}

				evalOutput := &EvalOutput{
					AdditionalVariables: map[string]interface{}{},
					Violations:          violations,
				}

				err := mapstructure.Decode(expression.Value.(map[string]interface{}), evalOutput)
				if err != nil {
					panic(err)
				}

				// TODO here we could run evalOutput.Validate()
				for key, value := range moduleOutputs {
					if !slices.Contains([]string{"violation", "activities", "risks"}, key) {
						evalOutput.AdditionalVariables[key] = value
					}
				}

				result.EvalOutput = evalOutput
			}
		}
		output = append(output, result)
	}

	//compiler
	return output, nil
}

type PolicyProcessor struct {
	logger     hclog.Logger
	labels     map[string]string
	subjects   []*proto.SubjectReference
	components []*proto.ComponentReference
	actors     []*proto.OriginActor
	activities []*proto.Activity
}

func NewPolicyProcessor(
	logger hclog.Logger,
	labels map[string]string,
	subjects []*proto.SubjectReference,
	components []*proto.ComponentReference,
	actors []*proto.OriginActor,
	activities []*proto.Activity,
) *PolicyProcessor {
	return &PolicyProcessor{
		logger:     logger,
		labels:     labels,
		subjects:   subjects,
		components: components,
		actors:     actors,
		activities: activities,
	}
}

func (p *PolicyProcessor) GenerateResults(ctx context.Context, policyPath string, data interface{}) ([]*proto.Observation, []*proto.Finding, error) {
	var resultErr error
	activities := p.activities
	findings := make([]*proto.Finding, 0)
	observations := make([]*proto.Observation, 0)

	// Explicitly reset steps to make things readable
	activities = append(activities, &proto.Activity{
		Title:       "Execute policy",
		Description: "Prepare and compile policy bundles, and execute them using the prepared SSH configuration data",
		Steps: []*proto.Step{
			{
				Title:       "Compile policy bundle",
				Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
			},
			{
				Title:       "Execute policy bundle",
				Description: "Using previously collected JSON-formatted configuration, execute the compiled policies",
			},
		},
	})
	results, err := New(ctx, p.logger, policyPath).Execute(ctx, data)
	if err != nil {
		p.logger.Error("Failed to evaluate against policy bundle", "error", err)
		resultErr = errors.Join(resultErr, err)
		return observations, findings, resultErr
	}

	activities = append(activities, &proto.Activity{
		Title:       "Compile Results",
		Description: "Using the output from policy execution, compile the resulting output to Observations and Findings, marking any violations, risks, and other OSCAL-familiar data",
		Steps: []*proto.Step{
			{
				Title:       "Create lists of observations and findings",
				Description: "Using the policy execution output, create Observation and Findings objects from the resulting output.",
			},
		},
	})
	for _, result := range results {
		// Observation UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
		// This acts as an identifier to show the history of an observation.
		observation, err := p.newObservation(result, activities)
		if err != nil {
			resultErr = errors.Join(resultErr, err)
			continue
		}

		if len(result.Violations) == 0 {
			finding, err := p.newFinding(result, []*proto.Observation{observation})
			if err != nil {
				resultErr = errors.Join(resultErr, err)
				continue
			}

			observation.Title = FirstOf(result.Title, Pointer(fmt.Sprintf("Local SSH Validation on %s passed.", result.Policy.Package.PurePackage())))
			observation.Description = *FirstOf(result.Description, Pointer(fmt.Sprintf("Observed no violations on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage())))
			observation.Remarks = result.Remarks

			finding.Title = *FirstOf(result.Title, Pointer(fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())))
			finding.Description = *FirstOf(result.Description, Pointer(fmt.Sprintf("No violations found on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage())))
			finding.Remarks = result.Remarks

			finding.Status = &proto.FindingStatus{
				State: runner.FindingTargetStatusSatisfied,
			}

			observations = append(observations, observation)
			findings = append(findings, finding)
		}

		if len(result.Violations) > 0 {
			observation.Title = FirstOf(result.Title, Pointer(fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage())))
			observation.Description = *FirstOf(result.Description, Pointer(fmt.Sprintf("Observed %d violation(s) on the %s policy within the Local SSH Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())))
			observation.Remarks = result.Remarks
			observations = append(observations, observation)

			for _, violation := range result.Violations {
				finding, err := p.newFinding(result, []*proto.Observation{observation})
				if err != nil {
					resultErr = errors.Join(resultErr, err)
					continue
				}

				finding.Title = *FirstOf(violation.Title, result.Title, Pointer(fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())))
				finding.Description = *FirstOf(violation.Description, result.Description, Pointer(fmt.Sprintf("No violations found on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage())))
				finding.Remarks = FirstOf(violation.Remarks, result.Remarks)
				finding.Status = &proto.FindingStatus{
					State: runner.FindingTargetStatusNotSatisfied,
				}
				findings = append(findings, finding)
			}
		}
	}

	return observations, findings, resultErr
}

func (p *PolicyProcessor) newObservation(result Result, activities []*proto.Activity) (*proto.Observation, error) {
	observationUUIDMap := MergeMaps(p.labels, map[string]string{
		"type":        "observation",
		"policy":      result.Policy.Package.PurePackage(),
		"policy_file": result.Policy.File,
	})
	observationUUID, err := sdk.SeededUUID(observationUUIDMap)
	if err != nil {
		return nil, err
	}

	observation := proto.Observation{
		ID:         uuid.New().String(),
		UUID:       observationUUID.String(),
		Collected:  timestamppb.New(time.Now()),
		Origins:    []*proto.Origin{{Actors: p.actors}},
		Subjects:   p.subjects,
		Components: p.components,
		Activities: activities,
		RelevantEvidence: []*proto.RelevantEvidence{
			{
				Description: fmt.Sprintf("Policy %v was executed against the Local SSH configuration, using the Local SSH Compliance Plugin", result.Policy.Package.PurePackage()),
			},
		},
	}
	return &observation, nil
}

func (p *PolicyProcessor) newFinding(result Result, observations []*proto.Observation) (*proto.Finding, error) {
	// Finding UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
	// This acts as an identifier to show the history of a finding.
	findingUUIDMap := MergeMaps(p.labels, map[string]string{
		"type":        "finding",
		"policy":      result.Policy.Package.PurePackage(),
		"policy_file": result.Policy.File,
	})
	findingUUID, err := sdk.SeededUUID(findingUUIDMap)
	if err != nil {
		return nil, err
	}

	relatedObservations := make([]*proto.RelatedObservation, 0)
	for _, observation := range observations {
		relatedObservations = append(relatedObservations, &proto.RelatedObservation{
			ObservationUUID: observation.ID,
		})
	}

	controls := make([]*proto.ControlReference, 0)
	for _, control := range result.Controls {
		controls = append(controls, &proto.ControlReference{
			Class:        control.Class,
			ControlId:    control.ControlID,
			StatementIds: control.StatementIDs,
		})
	}

	finding := &proto.Finding{
		ID:        uuid.New().String(),
		UUID:      findingUUID.String(),
		Collected: timestamppb.New(time.Now()),
		Labels: MergeMaps(
			p.labels,
			map[string]string{
				"_policy":      result.Policy.Package.PurePackage(),
				"_policy_path": result.Policy.File,
			},
		),
		Origins:             []*proto.Origin{{Actors: p.actors}},
		Subjects:            p.subjects,
		Components:          p.components,
		RelatedObservations: relatedObservations,
		Controls:            controls,
	}

	return finding, nil
}
