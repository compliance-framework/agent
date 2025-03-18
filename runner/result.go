package runner

import (
	"context"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
)

type apiHelper struct {
	logger      hclog.Logger
	client      *sdk.Client
	agentLabels map[string]string
}

func NewApiHelper(logger hclog.Logger, agentStreamId uuid.UUID, client *sdk.Client, agentLabels map[string]string) *apiHelper {
	logger = logger.Named("api-helper")
	return &apiHelper{
		logger:      logger,
		client:      client,
		agentLabels: agentLabels,
	}
}

func (h *apiHelper) CreateObservationsAndFindings(ctx context.Context, req *proto.ComplianceInformationRequest) error {
	observations := *ObservationsProtoToSdk(req.GetObservations())
	findings := *FindingsProtoToSdk(req.GetFindings())

	for key, finding := range findings {
		labels := finding.Labels
		for k, v := range h.agentLabels {
			labels[k] = v
		}
		findings[key].Labels = labels
	}

	return h.client.ObservationsAndFindings.Create(ctx, observations, findings)
}
