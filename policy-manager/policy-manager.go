package policy_manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk"
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/rego"
	"google.golang.org/protobuf/types/known/timestamppb"
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
			evidence.Title = *FirstOf(result.Title, Pointer(""))
			evidence.Description = result.Description
			evidence.Remarks = result.Remarks
			evidence.Status = &proto.EvidenceStatus{
				Reason:  "pass",
				Remarks: *FirstOf(result.Remarks, Pointer("")),
				State:   proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED,
			}

			evidences = append(evidences, evidence)
		}

		if len(result.Violations) > 0 {
			evidence.Title = *FirstOf(result.Title, Pointer(""))
			evidence.Description = result.Description
			evidence.Remarks = result.Remarks
			evidences = append(evidences, evidence)
			evidence.Status = &proto.EvidenceStatus{
				Reason:  "fail",
				Remarks: *FirstOf(result.Remarks, Pointer("")),
				State:   proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_NOT_SATISFIED,
			}

			props := make([]*proto.Property, 0, len(result.Violations))
			for _, value := range result.Violations {
				if value.ID != nil {
					props = append(props, &proto.Property{
						Name:  "_violation_id",
						Value: *value.ID,
					})
				}
			}
			evidence.Props = props
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
				"_policy": result.Policy.Package.PurePackage(),
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

func (pm *PolicyManager) GetRiskTemplates(ctx context.Context) (map[string][]*proto.RiskTemplate, error) {
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

	allTemplates := map[string][]*proto.RiskTemplate{}

	for _, module := range query.Modules() {
		// Exclude any test files for this compilation
		if strings.HasSuffix(module.Package.Location.File, "_test.rego") {
			continue
		}

		policy := Policy{
			File:        module.Package.Location.File,
			Package:     Package(module.Package.Path.String()),
			Annotations: module.Annotations,
		}
		purePackage := policy.Package.PurePackage()

		riskTemplates, err := pm.evaluateRiskTemplates(ctx, policy)
		if err != nil {
			return nil, err
		}

		if _, exists := allTemplates[purePackage]; !exists {
			allTemplates[purePackage] = make([]*proto.RiskTemplate, 0)
		}

		moduleTemplates := make([]*proto.RiskTemplate, 0, len(riskTemplates))
		for _, riskTemplate := range riskTemplates {
			temp := &RiskTemplate{}
			if err := mapstructure.Decode(riskTemplate, temp); err != nil {
				return nil, err
			}

			template, err := newProtoRiskTemplate(policy, temp)
			if err != nil {
				return nil, err
			}

			moduleTemplates = append(moduleTemplates, template)
		}
		allTemplates[purePackage] = append(allTemplates[purePackage], moduleTemplates...)
	}

	totalTemplates := 0
	for _, t := range allTemplates {
		totalTemplates += len(t)
	}
	pm.logger.Trace("Finished processing risk_templates", "num_policies", len(allTemplates), "num_templates", totalTemplates)
	return allTemplates, nil
}

func (pm *PolicyManager) evaluateRiskTemplates(ctx context.Context, policy Policy) ([]interface{}, error) {
	regoArgs := []func(r *rego.Rego){
		rego.Query(fmt.Sprintf("%s.risk_templates", policy.Package)),
	}
	regoArgs = append(regoArgs, pm.loaderOptions...)

	evaluation, err := rego.New(regoArgs...).Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluate %q in %s: %w", "risk_templates", policy.File, err)
	}

	if len(evaluation) == 0 || len(evaluation[0].Expressions) == 0 {
		return nil, nil
	}

	raw := evaluation[0].Expressions[0].Value
	riskTemplates, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid risk_templates type %T, expected array", raw)
	}

	return riskTemplates, nil
}

func newProtoRiskTemplate(policy Policy, temp *RiskTemplate) (*proto.RiskTemplate, error) {
	threats := make([]*proto.Threat, 0, len(temp.Threats))
	for _, threat := range temp.Threats {
		threats = append(threats, &proto.Threat{
			System:     threat.System,
			ExternalID: threat.ExternalID,
			Title:      threat.Title,
			Url:        threat.Url,
		})
	}

	remediationTasks := make([]*proto.RemediationTask, 0, len(temp.Remediation.Tasks))
	for _, task := range temp.Remediation.Tasks {
		remediationTasks = append(remediationTasks, &proto.RemediationTask{
			Title: task.Title,
		})
	}

	remediation := &proto.Remediation{
		Title:       temp.Remediation.Title,
		Description: temp.Remediation.Description,
		Tasks:       remediationTasks,
	}

	templateUUID, err := sdk.SeededUUID(map[string]string{
		"type":        "risk_template",
		"name":        temp.Name,
		"policy":      policy.Package.PurePackage(),
		"policy_file": policy.File,
	})
	if err != nil {
		return nil, err
	}

	return &proto.RiskTemplate{
		UUID:           templateUUID.String(),
		PolicyPackage:  policy.Package.PurePackage(),
		Name:           temp.Name,
		Title:          temp.Title,
		Statement:      temp.Statement,
		LikelihoodHint: temp.LikelihoodHint,
		ImpactHint:     temp.ImpactHint,
		ViolationIds:   temp.ViolationIds,
		Threats:        threats,
		Remediation:    remediation,
	}, nil
}
