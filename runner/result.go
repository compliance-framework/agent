package runner

import (
	"github.com/compliance-framework/agent/runner/proto"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

type Result struct {
	Title        string                `json:"title"`
	Status       proto.ExecutionStatus `json:"status"`
	Error        error                 `json:"error"`
	Observations *[]*proto.Observation `json:"observations,omitempty"`
	Findings     *[]*proto.Finding     `json:"findings,omitempty"`
	Risks        *[]*proto.Risk        `json:"risks,omitempty"`
	Logs         *[]*proto.LogEntry    `json:"logs,omitempty"`
	StreamID     string                `json:"streamId"`
	Labels       map[string]string     `json:"labels"`
}

func ErrorResult(res *Result) *Result {
	res.Status = proto.ExecutionStatus_FAILURE
	return res
}

func LinksProtoToOscal(links []*proto.Link) *[]oscalTypes_1_1_3.Link {
	results := make([]oscalTypes_1_1_3.Link, 0)
	for _, link := range links {
		results = append(results, *LinkProtoToOscal(link))
	}
	return &results
}

func LinkProtoToOscal(link *proto.Link) *oscalTypes_1_1_3.Link {
	return &oscalTypes_1_1_3.Link{
		Href:             link.GetHref(),
		MediaType:        link.GetMediaType(),
		Rel:              link.GetRel().String(),
		ResourceFragment: link.GetResourceFragment(),
		Text:             link.GetText(),
	}
}

func PropertiesProtoToOscal(properties []*proto.Property) *[]oscalTypes_1_1_3.Property {
	results := make([]oscalTypes_1_1_3.Property, 0)
	for _, property := range properties {
		results = append(results, *PropertyProtoToOscal(property))
	}
	return &results
}

func PropertyProtoToOscal(property *proto.Property) *oscalTypes_1_1_3.Property {
	return &oscalTypes_1_1_3.Property{
		Class:   property.GetClass(),
		Group:   property.GetGroup(),
		Name:    property.GetName(),
		Ns:      property.GetNs(),
		Remarks: property.GetRemarks(),
		UUID:    property.GetUuid(),
		Value:   property.GetValue(),
	}
}

func RelevantEvidencesProtoToOscal(evidences []*proto.RelevantEvidence) *[]oscalTypes_1_1_3.RelevantEvidence {
	results := make([]oscalTypes_1_1_3.RelevantEvidence, 0)
	for _, evidence := range evidences {
		results = append(results, *RelevantEvidenceProtoToOscal(evidence))
	}
	return &results
}

func RelevantEvidenceProtoToOscal(evidence *proto.RelevantEvidence) *oscalTypes_1_1_3.RelevantEvidence {
	return &oscalTypes_1_1_3.RelevantEvidence{
		Description: evidence.GetDescription(),
		Href:        evidence.GetHref(),
		Links:       LinksProtoToOscal(evidence.Links),
		Props:       PropertiesProtoToOscal(evidence.Props),
		Remarks:     evidence.GetRemarks(),
	}
}

func ResponsiblePartiesProtoToOscal(parties []*proto.ResponsibleParty) *[]oscalTypes_1_1_3.ResponsibleParty {
	results := make([]oscalTypes_1_1_3.ResponsibleParty, 0)
	for _, party := range parties {
		results = append(results, *ResponsiblePartyProtoToOscal(party))
	}
	return &results
}

func ResponsiblePartyProtoToOscal(party *proto.ResponsibleParty) *oscalTypes_1_1_3.ResponsibleParty {
	return &oscalTypes_1_1_3.ResponsibleParty{
		Links:      LinksProtoToOscal(party.GetLinks()),
		PartyUuids: party.GetPartyUuids(),
		Props:      PropertiesProtoToOscal(party.GetProps()),
		Remarks:    party.GetRemarks(),
		RoleId:     party.GetRoleId(),
	}
}

func RelatedRisksProtoToOscal(risks []*proto.RelatedRisk) *[]oscalTypes_1_1_3.AssociatedRisk {
	results := make([]oscalTypes_1_1_3.AssociatedRisk, 0)
	for _, risk := range risks {
		results = append(results, *RelatedRiskProtoToOscal(risk))
	}
	return &results
}

func RelatedRiskProtoToOscal(risk *proto.RelatedRisk) *oscalTypes_1_1_3.AssociatedRisk {
	return &oscalTypes_1_1_3.AssociatedRisk{
		RiskUuid: risk.GetRiskUuid(),
	}
}

func ExcludeSubjectsProtoToOscal(subjects []*proto.SelectSubjectById) *[]oscalTypes_1_1_3.SelectSubjectById {
	results := make([]oscalTypes_1_1_3.SelectSubjectById, 0)
	for _, subject := range subjects {
		results = append(results, *ExcludeSubjectProtoToOscal(subject))
	}
	return &results
}

func ExcludeSubjectProtoToOscal(selectedSubject *proto.SelectSubjectById) *oscalTypes_1_1_3.SelectSubjectById {
	return &oscalTypes_1_1_3.SelectSubjectById{
		Links:       LinksProtoToOscal(selectedSubject.GetLinks()),
		Props:       PropertiesProtoToOscal(selectedSubject.GetProps()),
		Remarks:     selectedSubject.GetRemarks(),
		SubjectUuid: selectedSubject.GetSubjectUuid(),
		Type:        selectedSubject.GetType().String(),
	}
}

func IncludeSubjectsProtoToOscal(subjects []*proto.SelectSubjectById) *[]oscalTypes_1_1_3.SelectSubjectById {
	results := make([]oscalTypes_1_1_3.SelectSubjectById, 0)
	for _, subject := range subjects {
		results = append(results, *IncludeSubjectProtoToOscal(subject))
	}
	return &results
}

func IncludeSubjectProtoToOscal(selectedSubject *proto.SelectSubjectById) *oscalTypes_1_1_3.SelectSubjectById {
	return &oscalTypes_1_1_3.SelectSubjectById{
		Links:       LinksProtoToOscal(selectedSubject.GetLinks()),
		Props:       PropertiesProtoToOscal(selectedSubject.GetProps()),
		Remarks:     selectedSubject.GetRemarks(),
		SubjectUuid: selectedSubject.GetSubjectUuid(),
		Type:        selectedSubject.GetType().String(),
	}
}

func IncludeAllSubjectsProtoToOscal(subjects []*proto.IncludeAll) *[]oscalTypes_1_1_3.IncludeAll {
	results := make([]oscalTypes_1_1_3.IncludeAll, 0)
	for _, subject := range subjects {
		results = append(results, *IncludeAllSubjectProtoToOscal(subject))
	}
	return &results
}

func IncludeAllSubjectProtoToOscal(selectedSubject *proto.IncludeAll) *oscalTypes_1_1_3.IncludeAll {
	return &oscalTypes_1_1_3.IncludeAll{}
}

func SubjectReferencesProtoToOscal(subjects []*proto.SubjectReference) *[]oscalTypes_1_1_3.SubjectReference {
	results := make([]oscalTypes_1_1_3.SubjectReference, 0)
	for _, subject := range subjects {
		results = append(results, *SubjectReferenceProtoToOscal(subject))
	}
	return &results
}

func SubjectReferenceProtoToOscal(subject *proto.SubjectReference) *oscalTypes_1_1_3.SubjectReference {
	return &oscalTypes_1_1_3.SubjectReference{
		Links:       LinksProtoToOscal(subject.GetLinks()),
		Props:       PropertiesProtoToOscal(subject.GetProps()),
		Remarks:     subject.GetRemarks(),
		SubjectUuid: subject.GetSubjectUuid(),
		Title:       subject.GetTitle(),
		Type:        subject.GetType().String(),
	}
}

func SubjectsProtoToOscal(subjects []*proto.AssessmentSubject) *[]oscalTypes_1_1_3.AssessmentSubject {
	results := make([]oscalTypes_1_1_3.AssessmentSubject, 0)
	for _, subject := range subjects {
		results = append(results, *SubjectProtoToOscal(subject))
	}
	return &results
}

func SubjectProtoToOscal(subject *proto.AssessmentSubject) *oscalTypes_1_1_3.AssessmentSubject {
	return &oscalTypes_1_1_3.AssessmentSubject{
		Description:     subject.GetDescription(),
		ExcludeSubjects: ExcludeSubjectsProtoToOscal(subject.GetExcludeSubjects()),
		IncludeAll:      IncludeAllSubjectProtoToOscal(subject.GetIncludeAll()),
		IncludeSubjects: IncludeSubjectsProtoToOscal(subject.GetIncludeSubjects()),
		Links:           LinksProtoToOscal(subject.GetLinks()),
		Props:           PropertiesProtoToOscal(subject.GetProps()),
		Remarks:         subject.GetRemarks(),
		Type:            subject.GetType().String(),
	}
}

func IdentifiedSubjectsProtoToOscal(subjects []*proto.IdentifiedSubject) *[]oscalTypes_1_1_3.IdentifiedSubject {
	results := make([]oscalTypes_1_1_3.IdentifiedSubject, 0)
	for _, subject := range subjects {
		results = append(results, *IdentifiedSubjectProtoToOscal(subject))
	}
	return &results
}

func IdentifiedSubjectProtoToOscal(subject *proto.IdentifiedSubject) *oscalTypes_1_1_3.IdentifiedSubject {
	return &oscalTypes_1_1_3.IdentifiedSubject{
		SubjectPlaceholderUuid: subject.GetSubjectPlaceholderUuid(),
		Subjects:               *SubjectsProtoToOscal(subject.GetSubjects()),
	}
}

func RelatedTasksProtoToOscal(tasks []*proto.RelatedTask) *[]oscalTypes_1_1_3.RelatedTask {
	results := make([]oscalTypes_1_1_3.RelatedTask, 0)
	for _, _task := range tasks {
		results = append(results, *RelatedTaskProtoToOscal(_task))
	}
	return &results
}

func RelatedTaskProtoToOscal(task *proto.RelatedTask) *oscalTypes_1_1_3.RelatedTask {
	return &oscalTypes_1_1_3.RelatedTask{
		IdentifiedSubject:  IdentifiedSubjectProtoToOscal(task.GetIdentifiedSubject()),
		Links:              LinksProtoToOscal(task.GetLinks()),
		Props:              PropertiesProtoToOscal(task.GetProps()),
		Remarks:            task.GetRemarks(),
		ResponsibleParties: ResponsiblePartiesProtoToOscal(task.GetResponsibleParties()),
		Subjects:           SubjectsProtoToOscal(task.GetSubjects()),
		TaskUuid:           task.GetTaskUuid(),
	}
}

func OriginsProtoToOscal(origins []*proto.Origin) *[]oscalTypes_1_1_3.Origin {
	results := make([]oscalTypes_1_1_3.Origin, 0)
	for _, origin := range origins {
		results = append(results, *OriginProtoToOscal(origin))
	}
	return &results
}

func OriginProtoToOscal(origin *proto.Origin) *oscalTypes_1_1_3.Origin {
	return &oscalTypes_1_1_3.Origin{
		Actors:       *OriginActorsProtoToOscal(origin.GetActors()),
		RelatedTasks: RelatedTasksProtoToOscal(origin.GetRelatedTasks()),
	}
}

func OriginActorsProtoToOscal(actors []*proto.OriginActor) *[]oscalTypes_1_1_3.OriginActor {
	results := make([]oscalTypes_1_1_3.OriginActor, 0)
	for _, actor := range actors {
		results = append(results, *OriginActorProtoToOscal(actor))
	}
	return &results
}

func OriginActorProtoToOscal(actor *proto.OriginActor) *oscalTypes_1_1_3.OriginActor {
	return &oscalTypes_1_1_3.OriginActor{
		ActorUuid: actor.GetActorUuid(),
		Links:     LinksProtoToOscal(actor.GetLinks()),
		Props:     PropertiesProtoToOscal(actor.GetProps()),
		RoleId:    actor.GetRoleId(),
		Type:      actor.GetType().String(),
	}
}

func ObservationTypesProtoToOscal(types []proto.ObservationType) *[]string {
	results := make([]string, 0)
	for _, _type := range types {
		results = append(results, ObservationTypeProtoToOscal(_type))
	}
	return &results
}

func ObservationTypeProtoToOscal(method proto.ObservationType) string {
	return method.String()
}

func ObservationMethodsProtoToOscal(methods []proto.ObservationMethod) []string {
	results := make([]string, 0)
	for _, method := range methods {
		results = append(results, ObservationMethodProtoToOscal(method))
	}
	return results
}

func ObservationMethodProtoToOscal(method proto.ObservationMethod) string {
	return method.String()
}

func RelatedObservationsProtoToOscal(observations []*proto.RelatedObservation) *[]oscalTypes_1_1_3.RelatedObservation {
	results := make([]oscalTypes_1_1_3.RelatedObservation, 0)
	for _, observation := range observations {
		results = append(results, *RelatedObservationProtoToOscal(observation))
	}
	return &results
}

func RelatedObservationProtoToOscal(observation *proto.RelatedObservation) *oscalTypes_1_1_3.RelatedObservation {
	return &oscalTypes_1_1_3.RelatedObservation{
		ObservationUuid: observation.GetObservationUuid(),
	}
}

func ImplementationStatusProtoToOscal(status *proto.ImplementationStatus) *oscalTypes_1_1_3.ImplementationStatus {
	return &oscalTypes_1_1_3.ImplementationStatus{
		Remarks: status.GetRemarks(),
		State:   status.GetState().String(),
	}
}

func ObjectiveStatusProtoToOscal(status *proto.ObjectiveStatus) *oscalTypes_1_1_3.ObjectiveStatus {
	return &oscalTypes_1_1_3.ObjectiveStatus{
		Reason:  status.GetReason().String(),
		Remarks: status.GetRemarks(),
		State:   status.GetState().String(),
	}
}

func FindingTargetProtoToOscal(target *proto.FindingTarget) *oscalTypes_1_1_3.FindingTarget {
	return &oscalTypes_1_1_3.FindingTarget{
		Description:          target.GetDescription(),
		ImplementationStatus: ImplementationStatusProtoToOscal(target.GetImplementationStatus()),
		Links:                LinksProtoToOscal(target.GetLinks()),
		Props:                PropertiesProtoToOscal(target.GetProps()),
		Remarks:              target.GetRemarks(),
		Status:               *ObjectiveStatusProtoToOscal(target.GetStatus()),
		TargetId:             target.GetTargetId(),
		Title:                target.GetTitle(),
		Type:                 target.GetType().String(),
	}
}

func ObservationsProtoToOscal(observations []*proto.Observation) *[]oscalTypes_1_1_3.Observation {
	results := make([]oscalTypes_1_1_3.Observation, 0)
	for _, observation := range observations {
		results = append(results, *ObservationProtoToOscal(observation))
	}
	return &results
}

func ObservationProtoToOscal(observation *proto.Observation) *oscalTypes_1_1_3.Observation {
	expires := observation.GetExpires().AsTime()

	return &oscalTypes_1_1_3.Observation{
		UUID:             observation.GetUuid(),
		Title:            observation.GetTitle(),
		Description:      observation.GetDescription(),
		Remarks:          observation.GetRemarks(),
		Collected:        observation.GetCollected().AsTime(),
		Expires:          &expires,
		Links:            LinksProtoToOscal(observation.GetLinks()),
		Props:            PropertiesProtoToOscal(observation.GetProps()),
		Subjects:         SubjectReferencesProtoToOscal(observation.GetSubjects()),
		RelevantEvidence: RelevantEvidencesProtoToOscal(observation.GetRelevantEvidence()),
		Methods:          ObservationMethodsProtoToOscal(observation.GetMethods()),
		Origins:          OriginsProtoToOscal(observation.GetOrigins()),
		Types:            ObservationTypesProtoToOscal(observation.GetTypes()),
	}
}

func FindingsProtoToOscal(findings []*proto.Finding) *[]oscalTypes_1_1_3.Finding {
	results := make([]oscalTypes_1_1_3.Finding, 0)
	for _, finding := range findings {
		results = append(results, *FindingProtoToOscal(finding))
	}
	return &results
}

func FindingProtoToOscal(finding *proto.Finding) *oscalTypes_1_1_3.Finding {
	return &oscalTypes_1_1_3.Finding{
		UUID:                        finding.GetUuid(),
		Title:                       finding.GetTitle(),
		Description:                 finding.GetDescription(),
		ImplementationStatementUuid: finding.GetImplementationStatementUuid(),
		Remarks:                     finding.GetRemarks(),
		Links:                       LinksProtoToOscal(finding.GetLinks()),
		Origins:                     OriginsProtoToOscal(finding.GetOrigins()),
		Props:                       PropertiesProtoToOscal(finding.GetProps()),
		RelatedObservations:         RelatedObservationsProtoToOscal(finding.GetRelatedObservations()),
		RelatedRisks:                RelatedRisksProtoToOscal(finding.GetRelatedRisks()),
		Target:                      *FindingTargetProtoToOscal(finding.Target),
	}
}

func ResultProtoToOscal(result *proto.AssessmentResult) *oscalTypes_1_1_3.Result {
	endTime := result.GetEnd().AsTime()
	return &oscalTypes_1_1_3.Result{
		UUID:         result.GetUuid(),
		Title:        result.GetTitle(),
		Description:  result.GetDescription(),
		Start:        result.GetStart().AsTime(),
		End:          &endTime,
		Observations: ObservationsProtoToOscal(result.GetObservations()),
		Findings:     FindingsProtoToOscal(result.GetFindings()),
		Links:        LinksProtoToOscal(result.GetLinks()),
		Props:        PropertiesProtoToOscal(result.GetProps()),
		Remarks:      result.GetRemarks(),
		// TODO this comes when implemented in the protogen files.
		AssessmentLog:    nil,
		Attestations:     nil,
		LocalDefinitions: nil,
		ReviewedControls: oscalTypes_1_1_3.ReviewedControls{},
		Risks:            nil,
	}
}
