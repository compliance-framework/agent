package policy_manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/rego"
	"google.golang.org/protobuf/types/known/timestamppb"
	"slices"
	"strings"
	"time"
)

type EvalOutput struct {
	Title               *string            `mapstructure:"title,omitempty"`
	Description         *string            `mapstructure:"description,omitempty"`
	Remarks             *string            `mapstructure:"remarks,omitempty"`
	Labels              *map[string]string `mapstructure:"labels,omitempty"`
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

				fmt.Println(expression.Value.(map[string]interface{}))

				err := mapstructure.Decode(expression.Value.(map[string]interface{}), evalOutput)
				if err != nil {
					panic(err)
				}

				// TODO here we could run evalOutput.Validate()
				for key, value := range moduleOutputs {
					if !slices.Contains([]string{"violation", "labels"}, key) {
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
	logger         hclog.Logger
	labels         map[string]string
	subjects       []*proto.Subject
	components     []*proto.Component
	inventoryItems []*proto.InventoryItem
	actors         []*proto.OriginActor
	activities     []*proto.Activity
}

func NewPolicyProcessor(
	logger hclog.Logger,
	labels map[string]string,
	subjects []*proto.Subject,
	components []*proto.Component,
	inventoryItems []*proto.InventoryItem,
	actors []*proto.OriginActor,
	activities []*proto.Activity,
) *PolicyProcessor {
	return &PolicyProcessor{
		logger:         logger,
		labels:         labels,
		subjects:       subjects,
		components:     components,
		inventoryItems: inventoryItems,
		actors:         actors,
		activities:     activities,
	}
}

func (p *PolicyProcessor) GenerateResults(ctx context.Context, policyPath string, data interface{}) ([]*proto.Evidence, error) {
	var resultErr error
	activities := p.activities
	evidences := make([]*proto.Evidence, 0)

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
		return evidences, resultErr
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
		evidence, err := p.newEvidence(result, activities)
		if err != nil {
			resultErr = errors.Join(resultErr, err)
			continue
		}

		if len(result.Violations) == 0 {
			evidence.Title = *FirstOf(result.Title, Pointer(fmt.Sprintf("Local SSH Validation on %s passed.", result.Policy.Package.PurePackage())))
			evidence.Description = FirstOf(result.Description, Pointer(fmt.Sprintf("Observed no violations on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage())))
			evidence.Remarks = result.Remarks
			evidence.Status = &proto.EvidenceStatus{
				Reason:  "pass",
				Remarks: *FirstOf(result.Title, Pointer(fmt.Sprintf("Local SSH Validation on %s passed.", result.Policy.Package.PurePackage()))),
				State:   proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED,
			}

			evidences = append(evidences, evidence)
		}

		if len(result.Violations) > 0 {
			evidence.Title = *FirstOf(result.Title, Pointer(fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage())))
			evidence.Description = FirstOf(result.Description, Pointer(fmt.Sprintf("Observed %d violation(s) on the %s policy within the Local SSH Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())))
			evidence.Remarks = result.Remarks
			evidences = append(evidences, evidence)
			evidence.Status = &proto.EvidenceStatus{
				Reason:  "fail",
				Remarks: *FirstOf(result.Title, Pointer(fmt.Sprintf("Local SSH Validation on %s passed.", result.Policy.Package.PurePackage()))),
				State:   proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_NOT_SATISFIED,
			}
		}
	}

	return evidences, resultErr
}

func (p *PolicyProcessor) newEvidence(result Result, activities []*proto.Activity) (*proto.Evidence, error) {
	evidenceUUID, err := sdk.SeededUUID(MergeMaps(map[string]string{
		"type":        "evidence",
		"policy":      result.Policy.Package.PurePackage(),
		"policy_file": result.Policy.File,
	}, p.labels))
	if err != nil {
		return nil, err
	}

	resultLabels := map[string]string{}
	if result.Labels != nil {
		resultLabels = *result.Labels
	}
	evidence := proto.Evidence{
		UUID: evidenceUUID.String(),
		Labels: MergeMaps(
			map[string]string{
				"_policy":      result.Policy.Package.PurePackage(),
				"_policy_path": result.Policy.File,
			},
			p.labels,
			resultLabels,
		),
		Start:          timestamppb.New(time.Now()),
		End:            timestamppb.New(time.Now()),
		Origins:        []*proto.Origin{{Actors: p.actors}},
		Activities:     activities,
		InventoryItems: p.inventoryItems,
		Components:     p.components,
		Subjects:       p.subjects,
		Status:         nil,
	}
	return &evidence, nil
}
