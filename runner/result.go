package runner

import (
	"context"
	"errors"
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

// CreateEvidence sends evidence to the API. Evidence that carries a PolicyEvaluation has
// its artifacts stored first and refers to them by digest. Storage is strict: if an
// evaluation's artifacts cannot be stored, its evidence is held back and the error returned,
// while other evidence is still sent. If the API does not support artifacts, all evidence is
// sent as before, without digests.
func (h *apiHelper) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	refs, failed, unsupported := h.artifacts.storeEvaluations(ctx, evidence)
	if unsupported {
		h.logger.Warn("The API does not support policy artifacts; evidence is sent without them and cannot be played back. Upgrade the API.")
	}

	send := make([]*proto.Evidence, 0, len(evidence))
	var policyArtifacts []*types.PolicyArtifacts
	heldBack := 0
	for _, e := range evidence {
		var stored *types.PolicyArtifacts
		if evaluation := e.GetPolicyEvaluation(); evaluation != nil {
			key := evaluationKey(evaluation)
			if _, ok := failed[key]; ok {
				heldBack++
				continue
			}
			stored = refs[key]
		}
		send = append(send, e)
		policyArtifacts = append(policyArtifacts, stored)
	}

	var storeErr error
	for _, err := range failed {
		storeErr = errors.Join(storeErr, err)
	}
	if storeErr != nil {
		h.logger.Error("Holding back evidence whose policy artifacts could not be stored", "evidence_held_back", heldBack, "error", storeErr)
	}
	if len(send) == 0 {
		return storeErr
	}

	evidences := ProtoToSdk(send, EvidenceProtoToSdk)

	// Merge agent, config and finding labels all together.
	labelled := make([]types.Evidence, 0)
	for i, evid := range *evidences {
		evid.PolicyArtifacts = policyArtifacts[i]
		labels := make(map[string]string)
		for k, v := range h.agentLabels {
			labels[k] = v
		}
		for k, v := range evid.Labels {
			labels[k] = v
		}
		evid.Labels = labels

		labelled = append(labelled, *evid)
	}

	return errors.Join(h.client.Evidence.Create(ctx, labelled...), storeErr)
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
