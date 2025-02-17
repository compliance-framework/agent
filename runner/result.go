package runner

import (
	"github.com/compliance-framework/agent/runner/proto"
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

func LinksProtoToOscal(links []*proto.Link) *[]oscaltypes113.Link {
	results := make([]oscaltypes113.Link, 0)
	for _, link := range links {
		results = append(results, *LinkProtoToOscal(link))
	}
	return &results
}

func LinkProtoToOscal(link *proto.Link) *oscaltypes113.Link {
	return &oscaltypes113.Link{
		Href:             link.GetHref(),
		MediaType:        link.GetMediaType(),
		Rel:              link.GetRel().String(),
		ResourceFragment: link.GetResourceFragment(),
		Text:             link.GetText(),
	}
}

func PropertiesProtoToOscal(properties []*proto.Property) *[]oscaltypes113.Property {
	results := make([]oscaltypes113.Property, 0)
	for _, property := range properties {
		results = append(results, *PropertyProtoToOscal(property))
	}
	return &results
}

func PropertyProtoToOscal(property *proto.Property) *oscaltypes113.Property {
	return &oscaltypes113.Property{
		Class:   property.GetClass(),
		Group:   property.GetGroup(),
		Name:    property.GetName(),
		Ns:      property.GetNs(),
		Remarks: property.GetRemarks(),
		UUID:    property.GetUuid(),
		Value:   property.GetValue(),
	}
}

func RelevantEvidencesProtoToOscal(evidences []*proto.RelevantEvidence) *[]oscaltypes113.RelevantEvidence {
	results := make([]oscaltypes113.RelevantEvidence, 0)
	for _, evidence := range evidences {
		results = append(results, *RelevantEvidenceProtoToOscal(evidence))
	}
	return &results
}

func RelevantEvidenceProtoToOscal(evidence *proto.RelevantEvidence) *oscaltypes113.RelevantEvidence {
	return &oscaltypes113.RelevantEvidence{
		Description: evidence.GetDescription(),
		Href:        evidence.GetHref(),
		Links:       LinksProtoToOscal(evidence.Links),
		Props:       PropertiesProtoToOscal(evidence.Props),
		Remarks:     evidence.GetRemarks(),
	}
}

func ResponsiblePartiesProtoToOscal(parties []*proto.ResponsibleParty) *[]oscaltypes113.ResponsibleParty {
	results := make([]oscaltypes113.ResponsibleParty, 0)
	for _, party := range parties {
		results = append(results, *ResponsiblePartyProtoToOscal(party))
	}
	return &results
}

func ResponsiblePartyProtoToOscal(party *proto.ResponsibleParty) *oscaltypes113.ResponsibleParty {
	return &oscaltypes113.ResponsibleParty{
		Links:      LinksProtoToOscal(party.GetLinks()),
		PartyUuids: party.GetPartyUuids(),
		Props:      PropertiesProtoToOscal(party.GetProps()),
		Remarks:    party.GetRemarks(),
		RoleId:     party.GetRoleId(),
	}
}

func RelatedRisksProtoToOscal(risks []*proto.RelatedRisk) *[]oscaltypes113.AssociatedRisk {
	results := make([]oscaltypes113.AssociatedRisk, 0)
	for _, risk := range risks {
		results = append(results, *RelatedRiskProtoToOscal(risk))
	}
	return &results
}

func RelatedRiskProtoToOscal(risk *proto.RelatedRisk) *oscaltypes113.AssociatedRisk {
	return &oscaltypes113.AssociatedRisk{
		RiskUuid: risk.GetRiskUuid(),
	}
}

func ExcludeSubjectsProtoToOscal(subjects []*proto.SelectSubjectById) *[]oscaltypes113.SelectSubjectById {
	results := make([]oscaltypes113.SelectSubjectById, 0)
	for _, subject := range subjects {
		results = append(results, *ExcludeSubjectProtoToOscal(subject))
	}
	return &results
}

func ExcludeSubjectProtoToOscal(selectedSubject *proto.SelectSubjectById) *oscaltypes113.SelectSubjectById {
	return &oscaltypes113.SelectSubjectById{
		Links:       LinksProtoToOscal(selectedSubject.GetLinks()),
		Props:       PropertiesProtoToOscal(selectedSubject.GetProps()),
		Remarks:     selectedSubject.GetRemarks(),
		SubjectUuid: selectedSubject.GetSubjectUuid(),
		Type:        selectedSubject.GetType().String(),
	}
}

func IncludeSubjectsProtoToOscal(subjects []*proto.SelectSubjectById) *[]oscaltypes113.SelectSubjectById {
	results := make([]oscaltypes113.SelectSubjectById, 0)
	for _, subject := range subjects {
		results = append(results, *IncludeSubjectProtoToOscal(subject))
	}
	return &results
}

func IncludeSubjectProtoToOscal(selectedSubject *proto.SelectSubjectById) *oscaltypes113.SelectSubjectById {
	return &oscaltypes113.SelectSubjectById{
		Links:       LinksProtoToOscal(selectedSubject.GetLinks()),
		Props:       PropertiesProtoToOscal(selectedSubject.GetProps()),
		Remarks:     selectedSubject.GetRemarks(),
		SubjectUuid: selectedSubject.GetSubjectUuid(),
		Type:        selectedSubject.GetType().String(),
	}
}

func IncludeAllSubjectsProtoToOscal(subjects []*proto.IncludeAll) *[]oscaltypes113.IncludeAll {
	results := make([]oscaltypes113.IncludeAll, 0)
	for _, subject := range subjects {
		results = append(results, *IncludeAllSubjectProtoToOscal(subject))
	}
	return &results
}

func IncludeAllSubjectProtoToOscal(selectedSubject *proto.IncludeAll) *oscaltypes113.IncludeAll {
	return &oscaltypes113.IncludeAll{}
}

func SubjectReferencesProtoToOscal(subjects []*proto.SubjectReference) *[]oscaltypes113.SubjectReference {
	results := make([]oscaltypes113.SubjectReference, 0)
	for _, subject := range subjects {
		results = append(results, *SubjectReferenceProtoToOscal(subject))
	}
	return &results
}

func SubjectReferenceProtoToOscal(subject *proto.SubjectReference) *oscaltypes113.SubjectReference {
	return &oscaltypes113.SubjectReference{
		Links:       LinksProtoToOscal(subject.GetLinks()),
		Props:       PropertiesProtoToOscal(subject.GetProps()),
		Remarks:     subject.GetRemarks(),
		SubjectUuid: subject.GetSubjectUuid(),
		Title:       subject.GetTitle(),
		Type:        subject.GetType().String(),
	}
}

func SubjectsProtoToOscal(subjects []*proto.AssessmentSubject) *[]oscaltypes113.AssessmentSubject {
	results := make([]oscaltypes113.AssessmentSubject, 0)
	for _, subject := range subjects {
		results = append(results, *SubjectProtoToOscal(subject))
	}
	return &results
}

func SubjectProtoToOscal(subject *proto.AssessmentSubject) *oscaltypes113.AssessmentSubject {
	return &oscaltypes113.AssessmentSubject{
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

func IdentifiedSubjectsProtoToOscal(subjects []*proto.IdentifiedSubject) *[]oscaltypes113.IdentifiedSubject {
	results := make([]oscaltypes113.IdentifiedSubject, 0)
	for _, subject := range subjects {
		results = append(results, *IdentifiedSubjectProtoToOscal(subject))
	}
	return &results
}

func IdentifiedSubjectProtoToOscal(subject *proto.IdentifiedSubject) *oscaltypes113.IdentifiedSubject {
	return &oscaltypes113.IdentifiedSubject{
		SubjectPlaceholderUuid: subject.GetSubjectPlaceholderUuid(),
		Subjects:               *SubjectsProtoToOscal(subject.GetSubjects()),
	}
}

func RelatedTasksProtoToOscal(tasks []*proto.RelatedTask) *[]oscaltypes113.RelatedTask {
	results := make([]oscaltypes113.RelatedTask, 0)
	for _, _task := range tasks {
		results = append(results, *RelatedTaskProtoToOscal(_task))
	}
	return &results
}

func RelatedTaskProtoToOscal(task *proto.RelatedTask) *oscaltypes113.RelatedTask {
	return &oscaltypes113.RelatedTask{
		IdentifiedSubject:  IdentifiedSubjectProtoToOscal(task.GetIdentifiedSubject()),
		Links:              LinksProtoToOscal(task.GetLinks()),
		Props:              PropertiesProtoToOscal(task.GetProps()),
		Remarks:            task.GetRemarks(),
		ResponsibleParties: ResponsiblePartiesProtoToOscal(task.GetResponsibleParties()),
		Subjects:           SubjectsProtoToOscal(task.GetSubjects()),
		TaskUuid:           task.GetTaskUuid(),
	}
}

func OriginsProtoToOscal(origins []*proto.Origin) *[]oscaltypes113.Origin {
	results := make([]oscaltypes113.Origin, 0)
	for _, origin := range origins {
		results = append(results, *OriginProtoToOscal(origin))
	}
	return &results
}

func OriginProtoToOscal(origin *proto.Origin) *oscaltypes113.Origin {
	return &oscaltypes113.Origin{
		Actors:       *OriginActorsProtoToOscal(origin.GetActors()),
		RelatedTasks: RelatedTasksProtoToOscal(origin.GetRelatedTasks()),
	}
}

func OriginActorsProtoToOscal(actors []*proto.OriginActor) *[]oscaltypes113.OriginActor {
	results := make([]oscaltypes113.OriginActor, 0)
	for _, actor := range actors {
		results = append(results, *OriginActorProtoToOscal(actor))
	}
	return &results
}

func OriginActorProtoToOscal(actor *proto.OriginActor) *oscaltypes113.OriginActor {
	return &oscaltypes113.OriginActor{
		ActorUuid: actor.GetActorUuid(),
		Links:     LinksProtoToOscal(actor.GetLinks()),
		Props:     PropertiesProtoToOscal(actor.GetProps()),
		RoleId:    actor.GetRoleId(),
		Type:      actor.GetType().String(),
	}
}

func ResponsibleRolesProtoToOscal(responsibleRoles []*proto.ResponsibleRole) *[]oscaltypes113.ResponsibleRole {
	results := make([]oscaltypes113.ResponsibleRole, 0)
	for _, responsibleRole := range responsibleRoles {
		results = append(results, *ResponsibleRoleProtoToOscal(responsibleRole))
	}
	return &results
}

func ResponsibleRoleProtoToOscal(responsibleRole *proto.ResponsibleRole) *oscaltypes113.ResponsibleRole {
	partyUuids := responsibleRole.GetPartyUuids()
	return &oscaltypes113.ResponsibleRole{
		Links:      LinksProtoToOscal(responsibleRole.GetLinks()),
		Props:      PropertiesProtoToOscal(responsibleRole.GetProps()),
		PartyUuids: &partyUuids,
		Remarks:    responsibleRole.GetRemarks(),
		RoleId:     responsibleRole.GetRoleId(),
	}
}

func ThreatIDsProtoToOscal(threatIds []*proto.ThreatId) *[]oscaltypes113.ThreatId {
	results := make([]oscaltypes113.ThreatId, 0)
	for _, threatId := range threatIds {
		results = append(results, *ThreatIDProtoToOscal(threatId))
	}
	return &results
}

func ThreatIDProtoToOscal(threatId *proto.ThreatId) *oscaltypes113.ThreatId {
	return &oscaltypes113.ThreatId{
		Href:   threatId.GetHref(),
		ID:     threatId.GetId(),
		System: threatId.GetSystem(),
	}
}

func LoggedBysProtoToOscal(logged []*proto.LoggedBy) *[]oscaltypes113.LoggedBy {
	results := make([]oscaltypes113.LoggedBy, 0)
	for _, logg := range logged {
		results = append(results, *LoggedByProtoToOscal(logg))
	}
	return &results
}

func LoggedByProtoToOscal(logged *proto.LoggedBy) *oscaltypes113.LoggedBy {
	return &oscaltypes113.LoggedBy{
		PartyUuid: logged.GetPartyUuid(),
		RoleId:    logged.GetRoleId(),
	}
}

func RelatedResponsesProtoToOscal(responses []*proto.RiskLog_Entry_RelatedResponse) *[]oscaltypes113.RiskResponseReference {
	results := make([]oscaltypes113.RiskResponseReference, 0)
	for _, response := range responses {
		results = append(results, *RelatedResponseProtoToOscal(response))
	}
	return &results
}

func RelatedResponseProtoToOscal(response *proto.RiskLog_Entry_RelatedResponse) *oscaltypes113.RiskResponseReference {
	return &oscaltypes113.RiskResponseReference{
		Links:        LinksProtoToOscal(response.GetLinks()),
		Props:        PropertiesProtoToOscal(response.GetProps()),
		RelatedTasks: RelatedTasksProtoToOscal(response.GetRelatedTasks()),
		Remarks:      response.GetRemarks(),
		ResponseUuid: response.GetResponseUuid(),
	}
}

func RiskLogEntriesProtoToOscal(entries []*proto.RiskLog_Entry) *[]oscaltypes113.RiskLogEntry {
	results := make([]oscaltypes113.RiskLogEntry, 0)
	for _, entry := range entries {
		results = append(results, *RiskLogEntryProtoToOscal(entry))
	}
	return &results
}

func RiskLogEntryProtoToOscal(entry *proto.RiskLog_Entry) *oscaltypes113.RiskLogEntry {
	end := entry.GetEnd().AsTime()
	return &oscaltypes113.RiskLogEntry{
		Description:      entry.GetDescription(),
		End:              &end,
		Links:            LinksProtoToOscal(entry.GetLinks()),
		LoggedBy:         LoggedBysProtoToOscal(entry.GetLoggedBy()),
		Props:            PropertiesProtoToOscal(entry.GetProps()),
		RelatedResponses: RelatedResponsesProtoToOscal(entry.GetRelatedResponses()),
		Remarks:          entry.GetRemarks(),
		Start:            entry.GetStart().AsTime(),
		StatusChange:     entry.GetStatusChange().String(),
		Title:            entry.GetTitle(),
		UUID:             entry.GetUuid(),
	}
}

func MitigatingFactorsProtoToOscal(factors []*proto.MitigatingFactor) *[]oscaltypes113.MitigatingFactor {
	results := make([]oscaltypes113.MitigatingFactor, 0)
	for _, factor := range factors {
		results = append(results, *MitigatingFactorProtoToOscal(factor))
	}
	return &results
}

func MitigatingFactorProtoToOscal(factor *proto.MitigatingFactor) *oscaltypes113.MitigatingFactor {
	return &oscaltypes113.MitigatingFactor{
		Description:        factor.GetDescription(),
		ImplementationUuid: factor.GetImplementationUuid(),
		Links:              LinksProtoToOscal(factor.GetLinks()),
		Props:              PropertiesProtoToOscal(factor.GetProps()),
		Subjects:           SubjectReferencesProtoToOscal(factor.GetSubjects()),
		UUID:               factor.GetUuid(),
	}
}

func FacetsProtoToOscal(facets []*proto.Facet) *[]oscaltypes113.Facet {
	results := make([]oscaltypes113.Facet, 0)
	for _, facet := range facets {
		results = append(results, *FacetProtoToOscal(facet))
	}
	return &results
}

func FacetProtoToOscal(facet *proto.Facet) *oscaltypes113.Facet {
	return &oscaltypes113.Facet{
		Links:   LinksProtoToOscal(facet.GetLinks()),
		Name:    facet.GetName(),
		Props:   PropertiesProtoToOscal(facet.GetProps()),
		Remarks: facet.GetRemarks(),
		System:  facet.GetSystem(),
		Value:   facet.GetValue(),
	}
}

func CharacterizationsProtoToOscal(characters []*proto.Characterization) *[]oscaltypes113.Characterization {
	results := make([]oscaltypes113.Characterization, 0)
	for _, character := range characters {
		results = append(results, *CharacterizationProtoToOscal(character))
	}
	return &results
}

func CharacterizationProtoToOscal(character *proto.Characterization) *oscaltypes113.Characterization {
	return &oscaltypes113.Characterization{
		Facets: *FacetsProtoToOscal(character.GetFacets()),
		Links:  LinksProtoToOscal(character.GetLinks()),
		Origin: *OriginProtoToOscal(character.GetOrigin()),
		Props:  PropertiesProtoToOscal(character.GetProps()),
	}
}

func RiskLogProtoToOscal(log *proto.RiskLog) *oscaltypes113.RiskLog {
	return &oscaltypes113.RiskLog{
		Entries: *RiskLogEntriesProtoToOscal(log.GetEntries()),
	}
}

func RisksProtoToOscal(risks []*proto.Risk) *[]oscaltypes113.Risk {
	results := make([]oscaltypes113.Risk, 0)
	for _, risk := range risks {
		results = append(results, *RiskProtoToOscal(risk))
	}
	return &results
}

func RiskProtoToOscal(risk *proto.Risk) *oscaltypes113.Risk {
	deadline := risk.GetDeadline().AsTime()
	return &oscaltypes113.Risk{
		Characterizations:   CharacterizationsProtoToOscal(risk.GetCharacterizations()),
		Deadline:            &deadline,
		Description:         risk.GetDescription(),
		Links:               LinksProtoToOscal(risk.GetLinks()),
		MitigatingFactors:   MitigatingFactorsProtoToOscal(risk.GetMitigatingFactors()),
		Origins:             OriginsProtoToOscal(risk.GetOrigins()),
		Props:               PropertiesProtoToOscal(risk.GetProps()),
		RelatedObservations: RelatedObservationsProtoToOscal(risk.GetRelatedObservations()),
		Remediations:        ResponsesProtoToOscal(risk.GetRemediations()),
		RiskLog:             RiskLogProtoToOscal(risk.GetRiskLog()),
		Statement:           risk.GetStatement(),
		Status:              risk.GetStatus().String(),
		ThreatIds:           ThreatIDsProtoToOscal(risk.GetThreatIds()),
		Title:               risk.GetTitle(),
		UUID:                risk.GetUuid(),
	}
}

func TaskDependenciesProtoToOscal(deps []*proto.Task_TaskDependency) *[]oscaltypes113.TaskDependency {
	results := make([]oscaltypes113.TaskDependency, 0)
	for _, dep := range deps {
		results = append(results, *TaskDependencyProtoToOscal(dep))
	}
	return &results
}

func TaskDependencyProtoToOscal(dep *proto.Task_TaskDependency) *oscaltypes113.TaskDependency {
	return &oscaltypes113.TaskDependency{
		Remarks:  dep.GetRemarks(),
		TaskUuid: dep.GetTaskUuid(),
	}
}

func AssociatedActivitiesProtoToOscal(activities []*proto.Task_AssociatedActivity) *[]oscaltypes113.AssociatedActivity {
	results := make([]oscaltypes113.AssociatedActivity, 0)
	for _, activity := range activities {
		results = append(results, *AssociatedActivityProtoToOscal(activity))
	}
	return &results
}

func AssociatedActivityProtoToOscal(ac *proto.Task_AssociatedActivity) *oscaltypes113.AssociatedActivity {
	return &oscaltypes113.AssociatedActivity{
		ActivityUuid:     ac.GetActivityUuid(),
		Links:            LinksProtoToOscal(ac.GetLinks()),
		Props:            PropertiesProtoToOscal(ac.GetProps()),
		Remarks:          ac.GetRemarks(),
		ResponsibleRoles: ResponsibleRolesProtoToOscal(ac.GetResponsibleRoles()),
		Subjects:         *SubjectsProtoToOscal(ac.GetSubjects()),
	}
}

func AtFrequencyProtoToOscal(freq *proto.EventTiming_Frequency) *oscaltypes113.FrequencyCondition {
	return &oscaltypes113.FrequencyCondition{
		Period: int(freq.GetPeriod()),
		Unit:   freq.GetUnit().String(),
	}
}

func OnDateProtoToOscal(timing *proto.EventTiming) *oscaltypes113.OnDateCondition {
	return &oscaltypes113.OnDateCondition{
		Date: timing.GetOnDate().AsTime(),
	}
}

func OnDateRangeProtoToOscal(freq *proto.EventTiming_DateRange) *oscaltypes113.OnDateRangeCondition {
	return &oscaltypes113.OnDateRangeCondition{
		End:   freq.GetEnd().AsTime(),
		Start: freq.GetStart().AsTime(),
	}
}

func EventTimingProtoToOscal(timing *proto.EventTiming) *oscaltypes113.EventTiming {
	return &oscaltypes113.EventTiming{
		AtFrequency:     AtFrequencyProtoToOscal(timing.GetAtFrequency()),
		OnDate:          OnDateProtoToOscal(timing),
		WithinDateRange: OnDateRangeProtoToOscal(timing.GetWithinDateRange()),
	}
}

func TasksProtoToOscal(tasks []*proto.Task) *[]oscaltypes113.Task {
	results := make([]oscaltypes113.Task, 0)
	for _, task := range tasks {
		results = append(results, *TaskProtoToOscal(task))
	}
	return &results
}

func TaskProtoToOscal(task *proto.Task) *oscaltypes113.Task {
	return &oscaltypes113.Task{
		AssociatedActivities: AssociatedActivitiesProtoToOscal(task.GetAssociatedActivities()),
		Dependencies:         TaskDependenciesProtoToOscal(task.GetDependencies()),
		Description:          task.GetDescription(),
		Links:                LinksProtoToOscal(task.GetLinks()),
		Props:                PropertiesProtoToOscal(task.GetProps()),
		Remarks:              task.GetRemarks(),
		ResponsibleRoles:     ResponsibleRolesProtoToOscal(task.GetResponsibleRoles()),
		Subjects:             SubjectsProtoToOscal(task.GetSubjects()),
		Tasks:                TasksProtoToOscal(task.GetTasks()),
		Timing:               EventTimingProtoToOscal(task.GetTiming()),
		Title:                task.GetTitle(),
		Type:                 task.GetType().String(),
		UUID:                 task.GetUuid(),
	}
}

func RequiredAssetsProtoToOscal(assets []*proto.RequiredAsset) *[]oscaltypes113.RequiredAsset {
	results := make([]oscaltypes113.RequiredAsset, 0)
	for _, asset := range assets {
		results = append(results, *RequiredAssetProtoToOscal(asset))
	}
	return &results
}

func RequiredAssetProtoToOscal(asset *proto.RequiredAsset) *oscaltypes113.RequiredAsset {
	return &oscaltypes113.RequiredAsset{
		Description: asset.GetDescription(),
		Links:       LinksProtoToOscal(asset.GetLinks()),
		Props:       PropertiesProtoToOscal(asset.GetProps()),
		Remarks:     asset.GetRemarks(),
		Subjects:    SubjectReferencesProtoToOscal(asset.GetSubjects()),
		Title:       asset.GetTitle(),
		UUID:        asset.GetUuid(),
	}
}

func ResponsesProtoToOscal(responses []*proto.Response) *[]oscaltypes113.Response {
	results := make([]oscaltypes113.Response, 0)
	for _, response := range responses {
		results = append(results, *ResponseProtoToOscal(response))
	}
	return &results
}

func ResponseProtoToOscal(response *proto.Response) *oscaltypes113.Response {
	return &oscaltypes113.Response{
		Description:    response.GetDescription(),
		Lifecycle:      response.GetLifecycle().String(),
		Links:          LinksProtoToOscal(response.GetLinks()),
		Origins:        OriginsProtoToOscal(response.GetOrigins()),
		Props:          PropertiesProtoToOscal(response.GetProps()),
		Remarks:        response.GetRemarks(),
		RequiredAssets: RequiredAssetsProtoToOscal(response.GetRequiredAssets()),
		Tasks:          TasksProtoToOscal(response.GetTasks()),
		Title:          response.GetTitle(),
		UUID:           response.GetUuid(),
	}
}

func ObservationTypesProtoToOscal(types []proto.ObservationType) *[]string {
	results := make([]string, 0)
	for _, _type := range types {
		results = append(results, ObservationTypeProtoToOscal(_type))
	}
	return &results
}

func ObservationTypeProtoToOscal(_type proto.ObservationType) string {
	return _type.String()
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

func RelatedObservationsProtoToOscal(observations []*proto.RelatedObservation) *[]oscaltypes113.RelatedObservation {
	results := make([]oscaltypes113.RelatedObservation, 0)
	for _, observation := range observations {
		results = append(results, *RelatedObservationProtoToOscal(observation))
	}
	return &results
}

func RelatedObservationProtoToOscal(observation *proto.RelatedObservation) *oscaltypes113.RelatedObservation {
	return &oscaltypes113.RelatedObservation{
		ObservationUuid: observation.GetObservationUuid(),
	}
}

func ImplementationStatusProtoToOscal(status *proto.ImplementationStatus) *oscaltypes113.ImplementationStatus {
	return &oscaltypes113.ImplementationStatus{
		Remarks: status.GetRemarks(),
		State:   status.GetState().String(),
	}
}

func ObjectiveStatusProtoToOscal(status *proto.ObjectiveStatus) *oscaltypes113.ObjectiveStatus {
	return &oscaltypes113.ObjectiveStatus{
		Reason:  status.GetReason(),
		Remarks: status.GetRemarks(),
		State:   status.GetState(),
	}
}

func FindingTargetProtoToOscal(target *proto.FindingTarget) *oscaltypes113.FindingTarget {
	return &oscaltypes113.FindingTarget{
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

func ObservationsProtoToOscal(observations []*proto.Observation) *[]oscaltypes113.Observation {
	results := make([]oscaltypes113.Observation, 0)
	for _, observation := range observations {
		results = append(results, *ObservationProtoToOscal(observation))
	}
	return &results
}

func ObservationProtoToOscal(observation *proto.Observation) *oscaltypes113.Observation {
	expires := observation.GetExpires().AsTime()

	return &oscaltypes113.Observation{
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

func FindingsProtoToOscal(findings []*proto.Finding) *[]oscaltypes113.Finding {
	results := make([]oscaltypes113.Finding, 0)
	for _, finding := range findings {
		results = append(results, *FindingProtoToOscal(finding))
	}
	return &results
}

func FindingProtoToOscal(finding *proto.Finding) *oscaltypes113.Finding {
	return &oscaltypes113.Finding{
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
		Target:                      *FindingTargetProtoToOscal(finding.GetTarget()),
	}
}

func SelectControlByIdsProtoToOscal(selectControls []*proto.SelectControlById) *[]oscaltypes113.AssessedControlsSelectControlById {
	results := make([]oscaltypes113.AssessedControlsSelectControlById, 0)
	for _, selectControl := range selectControls {
		results = append(results, *SelectControlByIdProtoToOscal(selectControl))
	}
	return &results
}

func SelectControlByIdProtoToOscal(selectControl *proto.SelectControlById) *oscaltypes113.AssessedControlsSelectControlById {
	statementIds := selectControl.GetStatementIds()
	return &oscaltypes113.AssessedControlsSelectControlById{
		ControlId:    selectControl.GetControlId(),
		StatementIds: &statementIds,
	}
}

func SelectObjectivesByIdsProtoToOscal(selectObjectives []*proto.SelectObjectiveById) *[]oscaltypes113.SelectObjectiveById {
	results := make([]oscaltypes113.SelectObjectiveById, 0)
	for _, selectObjective := range selectObjectives {
		results = append(results, *SelectObjectiveByIdProtoToOscal(selectObjective))
	}
	return &results
}

func SelectObjectiveByIdProtoToOscal(selectObjective *proto.SelectObjectiveById) *oscaltypes113.SelectObjectiveById {
	return &oscaltypes113.SelectObjectiveById{
		ObjectiveId: selectObjective.GetObjectiveId(),
	}
}

func ControlSelectionsProtoToOscal(selections []*proto.ReviewedControls_ControlSelection) *[]oscaltypes113.AssessedControls {
	results := make([]oscaltypes113.AssessedControls, 0)
	for _, selection := range selections {
		results = append(results, *ControlSelectionProtoToOscal(selection))
	}
	return &results
}

func ControlSelectionProtoToOscal(selection *proto.ReviewedControls_ControlSelection) *oscaltypes113.AssessedControls {
	return &oscaltypes113.AssessedControls{
		Description:     selection.GetDescription(),
		Links:           LinksProtoToOscal(selection.GetLinks()),
		Props:           PropertiesProtoToOscal(selection.GetProps()),
		Remarks:         selection.GetRemarks(),
		ExcludeControls: SelectControlByIdsProtoToOscal(selection.GetExcludeControls()),
		//IncludeAll:      finding.GetIncludeAll().(oscaltypes113.IncludeAll),
		IncludeControls: SelectControlByIdsProtoToOscal(selection.GetIncludeControls()),
	}
}

func ReferencedControlObjectivesProtoToOscal(cos []*proto.ReviewedControls_ControlObjectiveSelection) *[]oscaltypes113.ReferencedControlObjectives {
	results := make([]oscaltypes113.ReferencedControlObjectives, 0)
	for _, co := range cos {
		results = append(results, *ReferencedControlObjectiveProtoToOscal(co))
	}
	return &results
}

func ReferencedControlObjectiveProtoToOscal(co *proto.ReviewedControls_ControlObjectiveSelection) *oscaltypes113.ReferencedControlObjectives {
	return &oscaltypes113.ReferencedControlObjectives{
		Description:       co.GetDescription(),
		ExcludeObjectives: SelectObjectivesByIdsProtoToOscal(co.GetExcludeObjectives()),
		//IncludeAll:        nil,
		IncludeObjectives: SelectObjectivesByIdsProtoToOscal(co.GetIncludeObjectives()),
		Links:             LinksProtoToOscal(co.GetLinks()),
		Props:             PropertiesProtoToOscal(co.GetProps()),
		Remarks:           co.GetRemarks(),
	}
}

func ReviewedControlsProtoToOscal(controls []*proto.ReviewedControls) *[]oscaltypes113.ReviewedControls {
	results := make([]oscaltypes113.ReviewedControls, 0)
	for _, control := range controls {
		results = append(results, *ReviewedControlProtoToOscal(control))
	}
	return &results
}

func ReviewedControlProtoToOscal(reviewedControls *proto.ReviewedControls) *oscaltypes113.ReviewedControls {
	return &oscaltypes113.ReviewedControls{
		ControlObjectiveSelections: ReferencedControlObjectivesProtoToOscal(reviewedControls.GetControlObjectiveSelections()),
		ControlSelections:          *ControlSelectionsProtoToOscal(reviewedControls.GetControlSelections()),
		Description:                reviewedControls.GetDescription(),
		Links:                      LinksProtoToOscal(reviewedControls.GetLinks()),
		Props:                      PropertiesProtoToOscal(reviewedControls.GetProps()),
		Remarks:                    reviewedControls.GetRemarks(),
	}
}

func AssessmentPartsProtoToOscal(parts []*proto.AssessmentPart) *[]oscaltypes113.AssessmentPart {
	results := make([]oscaltypes113.AssessmentPart, 0)
	for _, part := range parts {
		results = append(results, *AssessmentPartProtoToOscal(part))
	}
	return &results
}

func AssessmentPartProtoToOscal(part *proto.AssessmentPart) *oscaltypes113.AssessmentPart {
	return &oscaltypes113.AssessmentPart{
		Class: part.GetClass(),
		Links: LinksProtoToOscal(part.GetLinks()),
		Name:  part.GetName().String(),
		Ns:    part.GetNs(),
		Parts: AssessmentPartsProtoToOscal(part.GetParts()),
		Props: PropertiesProtoToOscal(part.GetProps()),
		Prose: part.GetProse(),
		Title: part.GetTitle(),
		UUID:  part.GetUuid(),
	}
}

func AttestationsProtoToOscal(attestations []*proto.Attestation) *[]oscaltypes113.AttestationStatements {
	results := make([]oscaltypes113.AttestationStatements, 0)
	for _, attestation := range attestations {
		results = append(results, *AttestationProtoToOscal(attestation))
	}
	return &results
}

func AttestationProtoToOscal(attestation *proto.Attestation) *oscaltypes113.AttestationStatements {
	return &oscaltypes113.AttestationStatements{
		Parts:              *AssessmentPartsProtoToOscal(attestation.GetParts()),
		ResponsibleParties: ResponsiblePartiesProtoToOscal(attestation.GetResponsibleParties()),
	}
}

func AssessmentLogEntriesProtoToOscal(entries []*proto.AssessmentLog_Entry) *[]oscaltypes113.AssessmentLogEntry {
	results := make([]oscaltypes113.AssessmentLogEntry, 0)
	for _, entry := range entries {
		results = append(results, *AssessmentLogEntryProtoToOscal(entry))
	}
	return &results
}

func AssessmentLogEntryProtoToOscal(entry *proto.AssessmentLog_Entry) *oscaltypes113.AssessmentLogEntry {
	end := entry.GetEnd().AsTime()
	return &oscaltypes113.AssessmentLogEntry{
		Description:  entry.GetDescription(),
		End:          &end,
		Links:        LinksProtoToOscal(entry.GetLinks()),
		LoggedBy:     LoggedBysProtoToOscal(entry.GetLoggedBy()),
		Props:        PropertiesProtoToOscal(entry.GetProps()),
		RelatedTasks: RelatedTasksProtoToOscal(entry.GetRelatedTasks()),
		Remarks:      entry.GetRemarks(),
		Start:        entry.GetStart().AsTime(),
		Title:        entry.GetTitle(),
		UUID:         entry.GetUuid(),
	}
}

func AssessmentLogProtoToOscal(log *proto.AssessmentLog) *oscaltypes113.AssessmentLog {
	return &oscaltypes113.AssessmentLog{
		Entries: *AssessmentLogEntriesProtoToOscal(log.GetEntries()),
	}
}

func ResultProtoToOscal(result *proto.AssessmentResult) *oscaltypes113.Result {
	endTime := result.GetEnd().AsTime()
	return &oscaltypes113.Result{
		UUID:             result.GetUuid(),
		Title:            result.GetTitle(),
		Description:      result.GetDescription(),
		Start:            result.GetStart().AsTime(),
		End:              &endTime,
		Observations:     ObservationsProtoToOscal(result.GetObservations()),
		Findings:         FindingsProtoToOscal(result.GetFindings()),
		Links:            LinksProtoToOscal(result.GetLinks()),
		Props:            PropertiesProtoToOscal(result.GetProps()),
		Remarks:          result.GetRemarks(),
		AssessmentLog:    AssessmentLogProtoToOscal(result.GetAssessmentLog()),
		Attestations:     AttestationsProtoToOscal(result.GetAttestations()),
		LocalDefinitions: nil,
		ReviewedControls: *ReviewedControlProtoToOscal(result.GetReviewedControls()),
		Risks:            RisksProtoToOscal(result.GetRisks()),
	}
}

func strToTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
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
