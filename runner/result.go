package runner

import (
	"context"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/compliance-framework/configuration-service/sdk/types"
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

func (h *apiHelper) CreateFindings(ctx context.Context, finds []*proto.Finding) error {
	findings := *FindingsProtoToSdk(finds)

	// Merge agent, config and finding labels all together.
	resultFindings := make([]types.Finding, 0)
	for _, finding := range findings {
		labels := h.agentLabels
		for k, v := range finding.Labels {
			labels[k] = v
		}
		finding.Labels = labels
		resultFindings = append(resultFindings, finding)
	}

	err := h.client.Findings.Create(ctx, resultFindings)
	return err
}

func (h *apiHelper) CreateObservations(ctx context.Context, obs []*proto.Observation) error {
	observations := *ObservationsProtoToSdk(obs)
	err := h.client.Observations.Create(ctx, observations)
	return err
}
