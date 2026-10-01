package policy_manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/compliance-framework/api/sdk"
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/rego"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The evaluation core lives in the API module's policyeval package, shared with the API's
// playback endpoint so both evaluate policies identically. These aliases keep this
// package's exported names stable for plugins.
type EvalOutput = policyeval.EvalOutput

type PolicyManager struct {
	logger    hclog.Logger
	evaluator *policyeval.Evaluator
}

func New(ctx context.Context, logger hclog.Logger, policyPath string, policyData map[string]interface{}) *PolicyManager {
	return &PolicyManager{
		logger:    logger,
		evaluator: policyeval.NewFromBundlePath(policyPath, policyData, policyeval.Options{}),
	}
}

// NewWithEvaluator wraps an evaluator built by the caller, for example one restricted to
// policyeval.SandboxCapabilities. The agent uses it to dry-run inline bundles exactly the way
// plugins evaluate them.
func NewWithEvaluator(logger hclog.Logger, evaluator *policyeval.Evaluator) *PolicyManager {
	return &PolicyManager{logger: logger, evaluator: evaluator}
}

// RiskTemplateError is a failure to read the risk_templates of one policy package.
type RiskTemplateError struct {
	Package string // without the leading "data."
	File    string
	Err     error
}

func (e *RiskTemplateError) Error() string {
	return fmt.Sprintf("risk_templates of package %s (%s): %v", e.Package, e.File, e.Err)
}

func (e *RiskTemplateError) Unwrap() error { return e.Err }

func (pm *PolicyManager) prepareForEval(ctx context.Context, regoArgs ...func(r *rego.Rego)) (rego.PreparedEvalQuery, error) {
	return pm.evaluator.PrepareForEval(ctx, regoArgs...)
}

func (pm *PolicyManager) Execute(ctx context.Context, input interface{}) ([]Result, error) {
	pm.logger.Trace("Executing policy", "input", input)
	return pm.evaluator.Execute(ctx, input)
}

type PolicyProcessor struct {
	logger         hclog.Logger
	labels         map[string]string
	subjects       []*proto.Subject
	components     []*proto.Component
	inventoryItems []*proto.InventoryItem
	actors         []*proto.OriginActor
	activities     []*proto.Activity
	policyData     map[string]interface{}
}

func NewPolicyProcessor(
	logger hclog.Logger,
	labels map[string]string,
	subjects []*proto.Subject,
	components []*proto.Component,
	inventoryItems []*proto.InventoryItem,
	actors []*proto.OriginActor,
	activities []*proto.Activity,
	policyData map[string]interface{},
) *PolicyProcessor {
	return &PolicyProcessor{
		logger:         logger,
		labels:         labels,
		subjects:       subjects,
		components:     components,
		inventoryItems: inventoryItems,
		actors:         actors,
		activities:     activities,
		policyData:     policyData,
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
	results, err := New(ctx, p.logger, policyPath, p.policyData).Execute(ctx, data)
	if err != nil {
		p.logger.Error("Failed to evaluate against policy bundle", "error", err)
		resultErr = errors.Join(resultErr, err)
		return evidences, resultErr
	}

	evaluation, err := p.policyEvaluation(policyPath, data)
	if err != nil {
		p.logger.Error("Failed to record what the policy evaluation used", "error", err)
		return evidences, err
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
		// If skip_reason is set and non-empty, skip evidence production entirely
		if result.SkipReason != nil && *result.SkipReason != "" {
			p.logger.Debug("Skipping evidence for policy", "policy_file", result.Policy.File, "policy_package", result.Policy.Package.PurePackage(), "skip_reason", *result.SkipReason)
			continue
		}

		// Observation UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
		// This acts as an identifier to show the history of an observation.
		evidence, err := p.newEvidence(result, policyPath, activities)
		if err != nil {
			resultErr = errors.Join(resultErr, err)
			continue
		}
		evidence.PolicyEvaluation = evaluation

		if len(result.Violations) == 0 {
			evidence.Title = *result.Title
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
			evidence.Title = *result.Title
			evidence.Description = result.Description
			evidence.Remarks = result.Remarks
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

			evidences = append(evidences, evidence)
		}
	}

	return evidences, resultErr
}

// policyEvaluation records what an evaluation depended on, for the agent to upload as
// artifacts: the bundle path and the input and policy data as JSON. The API, not the plugin,
// canonicalises and hashes them.
func (p *PolicyProcessor) policyEvaluation(policyPath string, data interface{}) (*proto.PolicyEvaluation, error) {
	input, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("encode input data: %w", err)
	}
	evaluation := &proto.PolicyEvaluation{PolicyPath: policyPath, Input: input}
	if len(p.policyData) > 0 {
		if evaluation.PolicyData, err = json.Marshal(p.policyData); err != nil {
			return nil, fmt.Errorf("encode policy data: %w", err)
		}
	}
	return evaluation, nil
}

func validateNewEvidence(result Result) error {
	if result.Title == nil {
		return fmt.Errorf("evidence title is required")
	}

	return nil
}

// Evidence labels that name the policy an evidence came from.
const (
	labelPolicy     = "_policy"
	labelPolicyPath = "_policy_path"
	// labelPolicyID is the policy's policy_id, when it declares one (R74).
	labelPolicyID = "_policy_id"
)

// newEvidence builds the evidence for one policy result. policyPath is the path the agent
// passed the plugin for the result's bundle.
//
// The evidence UUID is seeded with the policy's package and file and the plugin's labels, so
// the same policy and subject always produce the same UUID: that is the evidence stream.
// When the policy declares a policy_id, policyeval.SeedPath replaces the file and, if the
// plugin labels carry one, the _policy_path seed value, so the stream follows the policy
// rather than where its bundle lives. Without a policy_id the seed is exactly what it has
// always been, so existing streams keep their UUIDs.
func (p *PolicyProcessor) newEvidence(result Result, policyPath string, activities []*proto.Activity) (*proto.Evidence, error) {
	if err := validateNewEvidence(result); err != nil {
		return nil, err
	}

	evidenceUUID, err := sdk.SeededUUID(p.evidenceSeed(result, policyPath))
	if err != nil {
		return nil, err
	}

	resultLabels := map[string]string{}
	if result.Labels != nil {
		resultLabels = *result.Labels
	}
	labels := MergeMaps(
		map[string]string{
			labelPolicy: result.Policy.Package.PurePackage(),
		},
		p.labels,
		resultLabels,
	)
	if result.Policy.ID != "" {
		// Set last: it records the identity the UUID was seeded with.
		labels[labelPolicyID] = result.Policy.ID
	}
	evidence := proto.Evidence{
		UUID:   evidenceUUID.String(),
		Labels: labels,
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

// evidenceSeed returns the values an evidence UUID is seeded with (see newEvidence). Only
// the seed changes for a policy_id: the evidence keeps the plugin's real _policy_path label.
func (p *PolicyProcessor) evidenceSeed(result Result, policyPath string) map[string]string {
	policyFile := result.Policy.File
	labels := p.labels
	if result.Policy.ID != "" {
		seedFile, seedPolicyPath := policyeval.SeedPath(result.Policy.ID, result.Policy.File, policyPath)
		policyFile = seedFile
		if _, ok := p.labels[labelPolicyPath]; ok {
			labels = MergeMaps(p.labels, map[string]string{labelPolicyPath: seedPolicyPath})
		}
	}
	return MergeMaps(map[string]string{
		"type":        "evidence",
		"policy":      result.Policy.Package.PurePackage(),
		"policy_file": policyFile,
	}, labels)
}

func (pm *PolicyManager) GetRiskTemplates(ctx context.Context) (map[string][]*proto.RiskTemplate, error) {
	query, err := pm.prepareForEval(ctx,
		rego.Query("data.compliance_framework"),
		rego.Package("compliance_framework"),
	)
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
			return nil, &RiskTemplateError{Package: purePackage, File: policy.File, Err: err}
		}

		if _, exists := allTemplates[purePackage]; !exists {
			allTemplates[purePackage] = make([]*proto.RiskTemplate, 0)
		}

		moduleTemplates := make([]*proto.RiskTemplate, 0, len(riskTemplates))
		for _, riskTemplate := range riskTemplates {
			temp := &RiskTemplate{}
			if err := mapstructure.Decode(riskTemplate, temp); err != nil {
				return nil, &RiskTemplateError{Package: purePackage, File: policy.File, Err: err}
			}

			template, err := newProtoRiskTemplate(policy, temp)
			if err != nil {
				return nil, &RiskTemplateError{Package: purePackage, File: policy.File, Err: err}
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
	query, err := pm.prepareForEval(ctx,
		rego.Query(fmt.Sprintf("%s.risk_templates", policy.Package)),
	)
	if err != nil {
		return nil, fmt.Errorf("prepare %q in %s: %w", "risk_templates", policy.File, err)
	}

	evaluation, err := query.Eval(ctx)
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
	threatRefs := make([]*proto.ThreatRef, 0, len(temp.ThreatRefs))
	for _, ref := range temp.ThreatRefs {
		threatRefs = append(threatRefs, &proto.ThreatRef{
			System:     ref.System,
			ExternalID: ref.ExternalID,
			Title:      ref.Title,
			Url:        ref.Url,
		})
	}

	var remediation *proto.Remediation
	if temp.Remediation != nil {
		remediationTasks := make([]*proto.RemediationTask, 0, len(temp.Remediation.Tasks))
		for _, task := range temp.Remediation.Tasks {
			remediationTasks = append(remediationTasks, &proto.RemediationTask{
				Title: task.Title,
			})
		}

		remediation = &proto.Remediation{
			Title:       temp.Remediation.Title,
			Description: temp.Remediation.Description,
			Tasks:       remediationTasks,
		}
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

	labelSchema := make([]*proto.RiskTemplateLabelSchema, 0, len(temp.LabelSchema))
	for _, ls := range temp.LabelSchema {
		labelSchema = append(labelSchema, &proto.RiskTemplateLabelSchema{
			Key:         ls.Key,
			Description: ls.Description,
		})
	}

	return &proto.RiskTemplate{
		UUID:            templateUUID.String(),
		PolicyPackage:   policy.Package.PurePackage(),
		Name:            temp.Name,
		Title:           temp.Title,
		Statement:       temp.Statement,
		LikelihoodHint:  temp.LikelihoodHint,
		ImpactHint:      temp.ImpactHint,
		ViolationIds:    temp.ViolationIds,
		ThreatRefs:      threatRefs,
		Remediation:     remediation,
		DedupeLabelKeys: temp.DedupeLabelKeys,
		LabelSchema:     labelSchema,
	}, nil
}
