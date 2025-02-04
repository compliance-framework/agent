package runner

import (
	"github.com/compliance-framework/agent/runner/proto"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"time"
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
		Href:             link.Href,
		MediaType:        link.MediaType,
		Rel:              link.Rel,
		ResourceFragment: link.ResourceFragment,
		Text:             link.Text,
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
		// TODO Implement the rest of the types
		Class:   "",
		Group:   "",
		Name:    property.Name,
		Ns:      "",
		Remarks: "",
		UUID:    "",
		Value:   property.Value,
	}
}

func EvidencesProtoToOscal(evidences []*proto.Evidence) *[]oscalTypes_1_1_3.RelevantEvidence {
	results := make([]oscalTypes_1_1_3.RelevantEvidence, 0)
	for _, evidence := range evidences {
		results = append(results, *EvidenceProtoToOscal(evidence))
	}
	return &results
}

func EvidenceProtoToOscal(evidence *proto.Evidence) *oscalTypes_1_1_3.RelevantEvidence {
	return &oscalTypes_1_1_3.RelevantEvidence{
		Description: evidence.Description,
		Href:        "",
		Links:       LinksProtoToOscal(evidence.Links),
		Props:       PropertiesProtoToOscal(evidence.Props),
		Remarks:     evidence.Remarks,
	}
}

func ObservationsProtoToOscal(observations []*proto.Observation) (*[]oscalTypes_1_1_3.Observation, error) {
	results := make([]oscalTypes_1_1_3.Observation, 0)
	for _, observation := range observations {
		oscalObservation, err := ObservationProtoToOscal(observation)
		if err != nil {
			return nil, err
		}
		results = append(results, *oscalObservation)
	}
	return &results, nil
}

func ObservationProtoToOscal(observation *proto.Observation) (*oscalTypes_1_1_3.Observation, error) {
	collected, err := strToTime(observation.Collected)
	if err != nil {
		return nil, err
	}
	expires, err := strToTime(observation.Expires)
	if err != nil {
		return nil, err
	}

	subjects := []oscalTypes_1_1_3.SubjectReference{
		{
			// TODO Implement the rest of the types
			Links:       nil,
			Props:       nil,
			Remarks:     "",
			SubjectUuid: observation.SubjectId,
			Title:       "",
			Type:        "",
		},
	}

	return &oscalTypes_1_1_3.Observation{
		UUID:        observation.Id,
		Title:       observation.Title,
		Description: observation.Description,
		Remarks:     observation.Remarks,

		Collected:        collected,
		Expires:          &expires,
		Links:            LinksProtoToOscal(observation.Links),
		Props:            PropertiesProtoToOscal(observation.Props),
		Subjects:         &subjects,
		RelevantEvidence: EvidencesProtoToOscal(observation.RelevantEvidence),

		Methods: nil, // Not Implemented Yet
		Origins: nil, // Not Implemented Yet
		Types:   nil, // Not Implemented Yet
	}, nil
}

func FindingsProtoToOscal(findings []*proto.Finding) (*[]oscalTypes_1_1_3.Finding, error) {
	results := make([]oscalTypes_1_1_3.Finding, 0)
	for _, finding := range findings {
		oscalFinding, err := FindingProtoToOscal(finding)
		if err != nil {
			return nil, err
		}
		results = append(results, *oscalFinding)
	}
	return &results, nil
}

func FindingProtoToOscal(finding *proto.Finding) (*oscalTypes_1_1_3.Finding, error) {
	relatedObservations := make([]oscalTypes_1_1_3.RelatedObservation, 0)
	for _, observation := range finding.RelatedObservations {
		relatedObservations = append(relatedObservations, oscalTypes_1_1_3.RelatedObservation{
			ObservationUuid: observation,
		})
	}

	return &oscalTypes_1_1_3.Finding{
		Title:       finding.Title,
		Description: finding.Description,
		Remarks:     finding.Remarks,
		Links:       LinksProtoToOscal(finding.Links),
		//Origins:                     nil,
		Props:               PropertiesProtoToOscal(finding.Props),
		RelatedObservations: &relatedObservations,
		//RelatedRisks:                finding.RelatedRisks,
		Target: oscalTypes_1_1_3.FindingTarget{
			Description: "",
			Links:       nil,
			Props:       nil,
			Remarks:     "",
			ImplementationStatus: &oscalTypes_1_1_3.ImplementationStatus{
				Remarks: "",
				State:   "",
			},
			Status: oscalTypes_1_1_3.ObjectiveStatus{
				Reason:  "",
				Remarks: "",
				State:   "",
			},
			TargetId: "",
			Title:    "",
			Type:     "",
		},
	}, nil
}
