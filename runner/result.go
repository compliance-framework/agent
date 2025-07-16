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
}

func NewApiHelper(logger hclog.Logger, client *sdk.Client, agentLabels map[string]string) *apiHelper {
	logger = logger.Named("api-helper")
	return &apiHelper{
		logger:      logger,
		client:      client,
		agentLabels: agentLabels,
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
		for k, v := range evid.Labels {
			labels[k] = v
		}
		evid.Labels = labels

		labelled = append(labelled, *evid)
	}

	err := h.client.Evidence.Create(ctx, labelled...)
	return err
}
