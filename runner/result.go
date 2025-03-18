package runner

import (
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/compliance-framework/configuration-service/sdk/types"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
)

type resultHelper struct {
	logger        hclog.Logger
	client        *sdk.Client
	agentStreamId uuid.UUID
	resultLabels  map[string]string
}

func NewResultsHelper(logger hclog.Logger, agentStreamId uuid.UUID, client *sdk.Client, resultLabels map[string]string) *resultHelper {
	logger = logger.Named("results-helper")
	return &resultHelper{
		logger:        logger,
		agentStreamId: agentStreamId,
		client:        client,
		resultLabels:  resultLabels,
	}
}

func (h *resultHelper) CreateResult(streamID string, labels map[string]string, policyPath string, result *proto.AssessmentResult) error {
	streamSeedMap := map[string]string{
		"agentStreamId": h.agentStreamId.String(),
		"streamId":      streamID,
	}

	streamId, err := sdk.SeededUUID(streamSeedMap)

	h.logger.Trace("Generated StreamId from map", "streamId", streamId, "streamSeedMap", streamSeedMap)

	if err != nil {
		return err
	}

	resultLabels := h.resultLabels
	resultLabels["_policy"] = policyPath
	for k, v := range labels {
		resultLabels[k] = v
	}

	sdkResult, err := ResultProtoToSDK(result, streamId, resultLabels)
	if err != nil {
		return err
	}

	_, err = h.client.Results.Create(sdkResult)
	return err
}

func LinksProtoToSdk(links []*proto.Link) *[]types.Link {
	results := make([]types.Link, 0)
	for _, link := range links {
		results = append(results, *LinkProtoToSdk(link))
	}
	return &results
}

func LinkProtoToSdk(link *proto.Link) *types.Link {
	return &types.Link{
		Href:             link.GetHref(),
		MediaType:        link.GetMediaType(),
		Rel:              link.GetRel(),
		ResourceFragment: link.GetResourceFragment(),
		Text:             link.GetText(),
	}
}

func PropertiesProtoToSdk(properties []*proto.Property) *[]types.Property {
	results := make([]types.Property, 0)
	for _, property := range properties {
		results = append(results, *PropertyProtoToSdk(property))
	}
	return &results
}

func PropertyProtoToSdk(property *proto.Property) *types.Property {
	return &types.Property{
		Class:   property.GetClass(),
		Group:   property.GetGroup(),
		Name:    property.GetName(),
		Ns:      property.GetNs(),
		Remarks: property.GetRemarks(),
		UUID:    property.GetUuid(),
		Value:   property.GetValue(),
	}
}

func RelevantEvidencesProtoToSdk(evidences []*proto.RelevantEvidence) *[]types.RelevantEvidence {
	results := make([]types.RelevantEvidence, 0)
	for _, evidence := range evidences {
		results = append(results, *RelevantEvidenceProtoToSdk(evidence))
	}
	return &results
}

func RelevantEvidenceProtoToSdk(evidence *proto.RelevantEvidence) *types.RelevantEvidence {
	return &types.RelevantEvidence{
		Description: evidence.GetDescription(),
		Href:        evidence.GetHref(),
		Links:       LinksProtoToSdk(evidence.Links),
		Props:       PropertiesProtoToSdk(evidence.Props),
		Remarks:     evidence.GetRemarks(),
	}
}

func SubjectReferencesProtoToSdk(subjects []*proto.SubjectReference) *[]types.SubjectReference {
	results := make([]types.SubjectReference, 0)
	for _, subject := range subjects {
		results = append(results, *SubjectReferenceProtoToSdk(subject))
	}
	return &results
}

func SubjectReferenceProtoToSdk(subject *proto.SubjectReference) *types.SubjectReference {
	return &types.SubjectReference{
		Title:      subject.GetTitle(),
		Remarks:    subject.GetRemarks(),
		Type:       subject.GetType(),
		Attributes: subject.GetAttributes(),
		Links:      LinksProtoToSdk(subject.GetLinks()),
		Props:      PropertiesProtoToSdk(subject.GetProps()),
	}
}

func OriginsProtoToSdk(origins []*proto.Origin) *[]types.Origin {
	results := make([]types.Origin, 0)
	for _, origin := range origins {
		results = append(results, *OriginProtoToSdk(origin))
	}
	return &results
}

func OriginProtoToSdk(origin *proto.Origin) *types.Origin {
	return &types.Origin{
		Actors: *OriginActorsProtoToSdk(origin.GetActors()),
	}
}

func OriginActorsProtoToSdk(actors []*proto.OriginActor) *[]types.OriginActor {
	results := make([]types.OriginActor, 0)
	for _, actor := range actors {
		results = append(results, *OriginActorProtoToSdk(actor))
	}
	return &results
}

func OriginActorProtoToSdk(actor *proto.OriginActor) *types.OriginActor {
	return &types.OriginActor{
		UUID:  actor.GetUUID(),
		Title: actor.GetTitle(),
		Type:  actor.GetType(),
		Links: LinksProtoToSdk(actor.GetLinks()),
		Props: PropertiesProtoToSdk(actor.GetProps()),
	}
}

func ThreatIDsProtoToSdk(threatIds []*proto.ThreatId) *[]types.ThreatId {
	results := make([]types.ThreatId, 0)
	for _, threatId := range threatIds {
		results = append(results, *ThreatIDProtoToSdk(threatId))
	}
	return &results
}

func ThreatIDProtoToSdk(threatId *proto.ThreatId) *types.ThreatId {
	return &types.ThreatId{
		Href:   threatId.GetHref(),
		ID:     threatId.GetID(),
		System: threatId.GetSystem(),
	}
}

func RisksProtoToSdk(risks []*proto.RiskReference) *[]types.RiskReference {
	results := make([]types.RiskReference, 0)
	for _, risk := range risks {
		results = append(results, *RiskProtoToSdk(risk))
	}
	return &results
}

func RiskProtoToSdk(risk *proto.RiskReference) *types.RiskReference {
	return &types.RiskReference{
		Identifier: risk.GetIdentifier(),
		Href:       risk.GetHref(),
		Status:     risk.GetStatus(),
		Origins:    OriginsProtoToSdk(risk.GetOrigins()),
		ThreatIds:  ThreatIDsProtoToSdk(risk.GetThreatIds()),
	}
}

func StepsProtoToSdk(steps []*proto.Step) *[]types.Step {
	results := make([]types.Step, 0)
	for _, step := range steps {
		results = append(results, *StepProtoToSdk(step))
	}
	return &results
}

func StepProtoToSdk(step *proto.Step) *types.Step {
	return &types.Step{
		UUID:        step.GetUUID(),
		Title:       step.GetTitle(),
		Description: step.GetDescription(),
		Remarks:     step.GetRemarks(),
		Links:       LinksProtoToSdk(step.GetLinks()),
		Props:       PropertiesProtoToSdk(step.GetProps()),
	}
}

func ActivitiesProtoToSdk(activities []*proto.Activity) *[]types.Activity {
	results := make([]types.Activity, 0)
	for _, activity := range activities {
		results = append(results, *ActivityProtoToSdk(activity))
	}
	return &results
}

func ActivityProtoToSdk(risk *proto.Activity) *types.Activity {
	return &types.Activity{
		UUID:        risk.GetUUID(),
		Title:       risk.GetTitle(),
		Description: risk.GetDescription(),
		Remarks:     risk.GetRemarks(),
		Steps:       StepsProtoToSdk(risk.GetSteps()),
		Links:       LinksProtoToSdk(risk.GetLinks()),
		Props:       PropertiesProtoToSdk(risk.GetProps()),
	}
}

func ComponentReferencesProtoToSdk(activities []*proto.ComponentReference) *[]types.ComponentReference {
	results := make([]types.ComponentReference, 0)
	for _, activity := range activities {
		results = append(results, *ComponentReferenceProtoToSdk(activity))
	}
	return &results
}

func ComponentReferenceProtoToSdk(reference *proto.ComponentReference) *types.ComponentReference {
	return &types.ComponentReference{
		Identifier: reference.GetIdentifier(),
		Href:       reference.GetHref(),
	}
}

func ControlReferencesProtoToSdk(controls []*proto.ControlReference) *[]types.ControlReference {
	results := make([]types.ControlReference, 0)
	for _, control := range controls {
		results = append(results, *ControlReferenceProtoToSdk(control))
	}
	return &results
}

func ControlReferenceProtoToSdk(control *proto.ControlReference) *types.ControlReference {
	statementIds := control.GetStatementIds()
	return &types.ControlReference{
		Class:        control.GetClass(),
		ControlId:    control.GetControlId(),
		StatementIds: &statementIds,
	}
}

func RelatedObservationsProtoToSdk(observations []*proto.RelatedObservation) *[]types.RelatedObservation {
	results := make([]types.RelatedObservation, 0)
	for _, observation := range observations {
		results = append(results, *RelatedObservationProtoToSdk(observation))
	}
	return &results
}

func RelatedObservationProtoToSdk(observation *proto.RelatedObservation) *types.RelatedObservation {
	return &types.RelatedObservation{
		ObservationUuid: observation.GetObservationUUID(),
	}
}

func FindingStatusProtoToSdk(status *proto.FindingStatus) *types.FindingStatus {
	return &types.FindingStatus{
		Title:       status.GetTitle(),
		Description: status.GetDescription(),
		Remarks:     status.GetRemarks(),
		State:       status.GetState(),
		Links:       LinksProtoToSdk(status.GetLinks()),
		Props:       PropertiesProtoToSdk(status.GetProps()),
	}
}

func ObservationsProtoToSdk(observations []*proto.Observation) *[]types.Observation {
	results := make([]types.Observation, 0)
	for _, observation := range observations {
		results = append(results, *ObservationProtoToSdk(observation))
	}
	return &results
}

func ObservationProtoToSdk(observation *proto.Observation) *types.Observation {
	methods := observation.GetMethods()
	return &types.Observation{
		UUID:             observation.GetUUID(),
		Title:            observation.GetTitle(),
		Description:      observation.GetDescription(),
		Remarks:          observation.GetRemarks(),
		Collected:        observation.GetCollected().AsTime(),
		Expires:          observation.GetExpires().AsTime(),
		Methods:          &methods,
		Links:            LinksProtoToSdk(observation.GetLinks()),
		Props:            PropertiesProtoToSdk(observation.GetProps()),
		Origins:          OriginsProtoToSdk(observation.GetOrigins()),
		Subjects:         SubjectReferencesProtoToSdk(observation.GetSubjects()),
		Activities:       ActivitiesProtoToSdk(observation.GetActivities()),
		Components:       ComponentReferencesProtoToSdk(observation.GetComponents()),
		RelevantEvidence: RelevantEvidencesProtoToSdk(observation.GetRelevantEvidence()),
	}
}

func FindingsProtoToSdk(findings []*proto.Finding) *[]types.Finding {
	results := make([]types.Finding, 0)
	for _, finding := range findings {
		results = append(results, *FindingProtoToSdk(finding))
	}
	return &results
}

func FindingProtoToSdk(finding *proto.Finding) *types.Finding {
	return &types.Finding{
		UUID:                finding.GetUUID(),
		Title:               finding.GetTitle(),
		Description:         finding.GetDescription(),
		Remarks:             finding.GetRemarks(),
		Labels:              finding.GetLabels(),
		Origins:             OriginsProtoToSdk(finding.GetOrigins()),
		Subjects:            SubjectReferencesProtoToSdk(finding.GetSubjects()),
		Components:          ComponentReferencesProtoToSdk(finding.GetComponents()),
		RelatedObservations: RelatedObservationsProtoToSdk(finding.GetRelatedObservations()),
		Controls:            ControlReferencesProtoToSdk(finding.GetControls()),
		Risks:               RisksProtoToSdk(finding.GetRisks()),
		Status:              *FindingStatusProtoToSdk(finding.GetStatus()),
		Links:               LinksProtoToSdk(finding.GetLinks()),
		Props:               PropertiesProtoToSdk(finding.GetProps()),
	}
}
