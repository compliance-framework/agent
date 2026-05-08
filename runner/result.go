package runner

import (
	"context"

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
}

const agentConfigHashLabel = "_agent_config_hash"

func NewApiHelper(logger hclog.Logger, client *sdk.Client, agentLabels map[string]string, pluginName string) *apiHelper {
	logger = logger.Named("api-helper")
	return &apiHelper{
		logger:      logger,
		client:      client,
		agentLabels: agentLabels,
		pluginName:  pluginName,
	}
}

func (h *apiHelper) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	evidences := ProtoToSdk(evidence, EvidenceProtoToSdk)

	// Merge agent, config and finding labels all together.
	labelled := make([]types.Evidence, 0)
	for _, evid := range *evidences {
		labels := make(map[string]string)
		for k, v := range h.agentLabels {
			labels[k] = v
		}
		if _, ok := labels["_plugin"]; !ok && h.pluginName != "" {
			labels["_plugin"] = h.pluginName
		}
		for k, v := range evid.Labels {
			if isReservedEvidenceLabel(k) {
				continue
			}
			labels[k] = v
		}
		evid.Labels = labels
		evidenceUUID, err := sdk.SeededUUID(labels)
		if err != nil {
			return err
		}
		evid.UUID = evidenceUUID

		labelled = append(labelled, *evid)
	}

	return h.client.Evidence.Create(ctx, labelled...)
}

func isReservedEvidenceLabel(key string) bool {
	switch key {
	case "_agent", "_plugin", agentConfigHashLabel:
		return true
	default:
		return false
	}
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
