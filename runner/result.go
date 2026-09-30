package runner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/hashicorp/go-hclog"
)

type apiHelper struct {
	logger      hclog.Logger
	client      *sdk.Client
	agentLabels map[string]string
	pluginName  string
	artifacts   *artifactUploader
}

type ApiHelperOption func(*apiHelper)

// WithPolicyPaths sets the policy bundle paths the plugin was given. The agent uploads only
// these bundles as artifacts, so a plugin cannot make the agent read anything else.
func WithPolicyPaths(paths []string) ApiHelperOption {
	return func(h *apiHelper) {
		for _, path := range paths {
			h.artifacts.policyPaths[filepath.Clean(path)] = struct{}{}
		}
	}
}

func NewApiHelper(logger hclog.Logger, client *sdk.Client, agentLabels map[string]string, pluginName string, opts ...ApiHelperOption) *apiHelper {
	logger = logger.Named("api-helper")
	h := &apiHelper{
		logger:      logger,
		client:      client,
		agentLabels: agentLabels,
		pluginName:  pluginName,
		artifacts:   newArtifactUploader(client),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// CreateEvidence sends a batch of evidence to the API, one evidence at a time.
func (h *apiHelper) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	sender := h.NewEvidenceSender(ctx)
	for _, e := range evidence {
		sender.Send(e)
	}
	return sender.Close()
}

// NewEvidenceSender returns a sender that handles each evidence as it arrives: for an
// evaluation not seen before it stores the artifacts, then it sends the evidence with their
// digests. Only the digests are kept, never the evaluation's data. Storage is strict: an
// evaluation whose artifacts cannot be stored has its evidence held back, and Close returns
// the error, while other evidence is still sent. If the API does not support artifacts,
// evidence is sent as before, without digests.
func (h *apiHelper) NewEvidenceSender(ctx context.Context) EvidenceSender {
	return &apiEvidenceSender{h: h, ctx: ctx, evaluations: map[string]evaluationOutcome{}}
}

type evaluationOutcome struct {
	refs *types.PolicyArtifacts
	err  error
}

type apiEvidenceSender struct {
	h           *apiHelper
	ctx         context.Context
	evaluations map[string]evaluationOutcome

	heldBack    int
	storeErr    error
	sendErr     error
	unsupported bool
}

func (s *apiEvidenceSender) Send(e *proto.Evidence) {
	var refs *types.PolicyArtifacts
	if evaluation := e.GetPolicyEvaluation(); evaluation != nil {
		outcome := s.outcome(evaluation)
		if outcome.err != nil {
			s.heldBack++
			return
		}
		refs = outcome.refs
	}
	if err := s.h.client.Evidence.Create(s.ctx, s.h.toSdk(e, refs)); err != nil {
		s.sendErr = errors.Join(s.sendErr, err)
	}
}

func (s *apiEvidenceSender) outcome(evaluation *proto.PolicyEvaluation) evaluationOutcome {
	key := evaluationKey(evaluation)
	if outcome, seen := s.evaluations[key]; seen {
		return outcome
	}

	var outcome evaluationOutcome
	if isReference(evaluation) {
		outcome.err = unknownEvaluation(evaluation.GetId())
	} else {
		refs, err := s.h.artifacts.storeEvaluation(s.ctx, evaluation)
		switch {
		case errors.Is(err, errArtifactsUnsupported):
			if !s.unsupported {
				s.unsupported = true
				s.h.logger.Warn("The API does not support policy artifacts; evidence is sent without them and cannot be played back. Upgrade the API.")
			}
		case err != nil:
			outcome.err = fmt.Errorf("store policy artifacts for %s: %w", evaluation.GetPolicyPath(), err)
		default:
			outcome.refs = refs
		}
	}
	if outcome.err != nil {
		s.storeErr = errors.Join(s.storeErr, outcome.err)
	}
	s.evaluations[key] = outcome
	return outcome
}

func (s *apiEvidenceSender) Close() error {
	if s.storeErr != nil {
		s.h.logger.Error("Holding back evidence whose policy artifacts could not be stored", "evidence_held_back", s.heldBack, "error", s.storeErr)
	}
	return errors.Join(s.sendErr, s.storeErr)
}

// toSdk converts evidence for the API, merging agent, config and finding labels, and
// referring to its stored artifacts. The evaluation's raw data is not included.
func (h *apiHelper) toSdk(e *proto.Evidence, refs *types.PolicyArtifacts) types.Evidence {
	evid := EvidenceProtoToSdk(e)
	evid.PolicyArtifacts = refs
	labels := make(map[string]string)
	for k, v := range h.agentLabels {
		labels[k] = v
	}
	for k, v := range evid.Labels {
		labels[k] = v
	}
	evid.Labels = labels
	return *evid
}

func (h *apiHelper) UpsertRiskTemplates(ctx context.Context, packageName string, riskTemplates []*proto.RiskTemplate) error {
	templates := ProtoToSdk(riskTemplates, RiskTemplateProtoToSdk)

	enriched := make([]types.RiskTemplate, 0)
	for _, temp := range *templates {
		temp = prepareRiskTemplateForUpsert(temp)
		if temp == nil {
			continue
		}

		enriched = append(enriched, *temp)
	}

	return h.client.RiskTemplate.Upsert(ctx, h.pluginName, packageName, enriched...)
}

func (h *apiHelper) UpsertSubjectTemplates(ctx context.Context, subjectTemplates []*proto.SubjectTemplate) error {
	templates := ProtoToSdk(subjectTemplates, SubjectTemplateProtoToSdk)

	enriched := make([]types.SubjectTemplate, 0)
	for _, temp := range *templates {
		if temp == nil {
			continue
		}

		temp.ID = optimisticUUID(temp.ID, map[string]string{
			"type":         "subject_template",
			"subject_type": temp.Type,
			"name":         temp.Name,
			"plugin_id":    h.pluginName,
		}).String()
		temp.SourceMode = "runtime-derived"
		temp.SelectorLabels = withPluginSelectorLabel(temp.SelectorLabels, h.pluginName)

		enriched = append(enriched, *temp)
	}
	return h.client.SubjectTemplate.Upsert(ctx, h.pluginName, enriched...)
}

func prepareRiskTemplateForUpsert(temp *types.RiskTemplate) *types.RiskTemplate {
	if temp == nil {
		return nil
	}

	isActive := true
	temp.IsActive = &isActive

	if temp.Remediation == nil {
		return temp
	}

	for i := range temp.Remediation.Tasks {
		temp.Remediation.Tasks[i].OrderIndex = i
	}

	return temp
}

func withPluginSelectorLabel(labels []types.SubjectTemplateSelectorLabel, pluginName string) []types.SubjectTemplateSelectorLabel {
	pluginSelectorLabel := "_plugin"
	result := make([]types.SubjectTemplateSelectorLabel, 0, len(labels)+1)
	replaced := false

	for _, label := range labels {
		if label.Key != pluginSelectorLabel {
			result = append(result, label)
			continue
		}

		if replaced {
			continue
		}

		label.Value = pluginName
		result = append(result, label)
		replaced = true
	}

	if replaced {
		return result
	}

	return append(result, types.SubjectTemplateSelectorLabel{
		Key:   pluginSelectorLabel,
		Value: pluginName,
	})
}
