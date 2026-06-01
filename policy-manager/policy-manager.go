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
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type EvalOutput struct {
	Title               *string            `mapstructure:"title,omitempty"`
	Description         *string            `mapstructure:"description,omitempty"`
	Remarks             *string            `mapstructure:"remarks,omitempty"`
	SkipReason          *string            `mapstructure:"skip_reason,omitempty"`
	Labels              *map[string]string `mapstructure:"labels,omitempty"`
	Violations          []Violation
	AdditionalVariables map[string]interface{}
}

type PolicyManager struct {
	logger        hclog.Logger
	loaderOptions []func(r *rego.Rego)
	policyData    map[string]interface{}
}

func New(ctx context.Context, logger hclog.Logger, policyPath string, policyData map[string]interface{}) *PolicyManager {
	return &PolicyManager{
		logger:        logger,
		policyData:    policyData,
		loaderOptions: []func(r *rego.Rego){rego.LoadBundle(policyPath)},
	}
}

func (pm *PolicyManager) prepareForEval(ctx context.Context, regoArgs ...func(r *rego.Rego)) (rego.PreparedEvalQuery, error) {
	store := inmem.New()
	txn, err := store.NewTransaction(ctx, storage.TransactionParams{Write: true})
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}

	committed := false
	defer func() {
		if !committed {
			store.Abort(ctx, txn)
		}
	}()

	args := make([]func(r *rego.Rego), 0, len(regoArgs)+len(pm.loaderOptions)+2)
	args = append(args,
		rego.Store(store),
		rego.Transaction(txn),
	)
	args = append(args, regoArgs...)
	args = append(args, pm.loaderOptions...)

	query, err := rego.New(args...).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}

	if err := writePolicyData(ctx, store, txn, pm.policyData); err != nil {
		return rego.PreparedEvalQuery{}, err
	}

	if err := store.Commit(ctx, txn); err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	committed = true

	// PreparedEvalQuery.Eval opens a fresh read transaction unless an
	// EvalTransaction is provided, so committing this write transaction makes the
	// loaded bundle and injected policy data visible to later evaluations.
	return query, nil
}

func writePolicyData(ctx context.Context, store storage.Store, txn storage.Transaction, data map[string]interface{}) error {
	for key, value := range data {
		if err := writePolicyDataValue(ctx, store, txn, storage.Path{key}, value); err != nil {
			return err
		}
	}
	return nil
}

func writePolicyDataValue(ctx context.Context, store storage.Store, txn storage.Transaction, path storage.Path, value interface{}) error {
	valueMap, valueIsMap := value.(map[string]interface{})
	if valueIsMap {
		existing, err := store.Read(ctx, txn, path)
		if err == nil {
			if _, ok := existing.(map[string]interface{}); ok {
				for key, nestedValue := range valueMap {
					nestedPath := append(append(storage.Path{}, path...), key)
					if err := writePolicyDataValue(ctx, store, txn, nestedPath, nestedValue); err != nil {
						return err
					}
				}
				return nil
			}
		} else if !storage.IsNotFound(err) {
			return err
		}
	}

	op := storage.AddOp
	if _, err := store.Read(ctx, txn, path); err == nil {
		op = storage.ReplaceOp
	} else if !storage.IsNotFound(err) {
		return err
	}

	if err := store.Write(ctx, txn, op, path, value); err != nil {
		return fmt.Errorf("write policy data at %q: %w", path.String(), err)
	}
	return nil
}

// normalizeViolationEntries converts OPA's two possible serializations of a
// `violation` rule into a uniform list of JSON byte slices that can be decoded
// into a Violation via the same path.
//
// Partial object rule (`violation[obj] := ...` / `violation[obj]`): OPA returns
// a map[string]interface{} whose keys are JSON-encoded violation objects.
//
// Set rule (`violation contains {...}`): OPA returns a []interface{} whose
// elements are already-decoded violation objects.
func normalizeViolationEntries(val interface{}) ([][]byte, error) {
	switch v := val.(type) {
	case map[string]interface{}:
		entries := make([][]byte, 0, len(v))
		for key := range v {
			entries = append(entries, []byte(key))
		}
		return entries, nil
	case []interface{}:
		entries := make([][]byte, 0, len(v))
		for _, item := range v {
			raw, err := json.Marshal(item)
			if err != nil {
				return nil, fmt.Errorf("re-encode violation entry: %w", err)
			}
			entries = append(entries, raw)
		}
		return entries, nil
	default:
		return nil, fmt.Errorf("unexpected violations type %T, want map or slice", val)
	}
}

func (pm *PolicyManager) Execute(ctx context.Context, input interface{}) ([]Result, error) {
	var output []Result

	pm.logger.Trace("Executing policy", "input", input)
	query, err := pm.prepareForEval(ctx,
		rego.Query("data.compliance_framework"),
		rego.Package("compliance_framework"),
	)
	if err != nil {
		return nil, err
	}

	for _, module := range query.Modules() {
		// Exclude any test files for this compilation
		if strings.HasSuffix(module.Package.Location.File, "_test.rego") {
			continue
		}

		// Only treat packages under the compliance_framework namespace as
		// evaluable policies. Packages in other namespaces (e.g. shared helper
		// libraries under ccf_libs) are bundled for import only and must not be
		// evaluated as policies, as they intentionally produce no title/evidence.
		packagePath := module.Package.Path.String()
		if packagePath != "data.compliance_framework" && !strings.HasPrefix(packagePath, "data.compliance_framework.") {
			continue
		}

		result := Result{
			Policy: Policy{
				File:        module.Package.Location.File,
				Package:     Package(module.Package.Path.String()),
				Annotations: module.Annotations,
			},
		}

		subQuery, err := pm.prepareForEval(ctx,
			rego.Query(module.Package.Path.String()),
			rego.Package(module.Package.Path.String()),
			rego.Input(input),
		)
		if err != nil {
			return nil, err
		}

		evaluation, err := subQuery.Eval(ctx)
		if err != nil {
			return nil, err
		}

		for _, eval := range evaluation {
			for _, expression := range eval.Expressions {
				moduleOutputs, ok := expression.Value.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf(
						"expected module outputs to be a map (policy package %q, file %q)",
						result.Policy.Package, result.Policy.File,
					)
				}
				violations := make([]Violation, 0)

				if val, ok := moduleOutputs["violation"]; ok {
					rawEntries, err := normalizeViolationEntries(val)
					if err != nil {
						return nil, fmt.Errorf(
							"%w (policy package %q, file %q)",
							err, result.Policy.Package, result.Policy.File,
						)
					}
					for _, raw := range rawEntries {
						viol := &Violation{}
						if err := json.Unmarshal(raw, viol); err != nil {
							return nil, fmt.Errorf(
								"decode violation entry (policy package %q, file %q): %w",
								result.Policy.Package, result.Policy.File, err,
							)
						}
						violations = append(violations, *viol)
					}
				}

				evalOutput := &EvalOutput{
					AdditionalVariables: map[string]interface{}{},
					Violations:          violations,
				}

				if err := mapstructure.Decode(moduleOutputs, evalOutput); err != nil {
					return nil, fmt.Errorf(
						"decode policy outputs (policy package %q, file %q): %w",
						result.Policy.Package, result.Policy.File, err,
					)
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
		evidence, err := p.newEvidence(result, activities)
		if err != nil {
			resultErr = errors.Join(resultErr, err)
			continue
		}

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

func validateNewEvidence(result Result) error {
	if result.Title == nil {
		return fmt.Errorf("evidence title is required")
	}

	return nil
}

func (p *PolicyProcessor) newEvidence(result Result, activities []*proto.Activity) (*proto.Evidence, error) {
	if err := validateNewEvidence(result); err != nil {
		return nil, err
	}

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
