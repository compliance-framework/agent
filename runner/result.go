package runner

import (
	"context"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
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

func (h *apiHelper) CreateObservationsAndFindings(ctx context.Context, obs []*proto.Observation, finds []*proto.Finding) error {
	observations := *ObservationsProtoToSdk(obs)
	findings := *FindingsProtoToSdk(finds)

	// Merge agent, config and finding labels all together.
	for _, finding := range findings {
		labels := h.agentLabels
		for k, v := range finding.Labels {
			labels[k] = v
		}
		finding.Labels = labels
	}

	return h.client.ObservationsAndFindings.Create(ctx, observations, findings)
}
