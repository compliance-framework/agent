package runner

import (
	"context"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

// InitWithSubjectsAndRisksFromPolicies is a helper for RunnerV2 plugins that handles
// the standard Init flow: upsert subject templates, then for each policy path parse
// risk templates and upsert them. Errors on subject template upsert are fatal; errors
// on individual policy paths or risk template packages are logged and skipped so that
// a single bad policy does not abort the rest.
func InitWithSubjectsAndRisksFromPolicies(
	ctx context.Context,
	logger hclog.Logger,
	req *proto.InitRequest,
	apiHelper ApiHelper,
	subjectTemplates []*proto.SubjectTemplate,
) (*proto.InitResponse, error) {
	if err := apiHelper.UpsertSubjectTemplates(ctx, subjectTemplates); err != nil {
		logger.Error("Error upserting subject templates", "error", err)
		return nil, err
	}

	for _, path := range req.PolicyPaths {
		pm := policyManager.New(ctx, logger, path)
		temps, err := pm.GetRiskTemplates(ctx)
		if err != nil {
			logger.Error("Error getting risk templates for policy path", "path", path, "error", err)
			continue
		}
		for packageName, templates := range temps {
			if err := apiHelper.UpsertRiskTemplates(ctx, packageName, templates); err != nil {
				logger.Error("Error upserting risk templates", "package", packageName, "error", err)
				continue
			}
		}
	}

	return &proto.InitResponse{}, nil
}
