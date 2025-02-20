package runner

import "github.com/compliance-framework/agent/runner/proto"

type CallableEvalResponse struct {
	*proto.EvalResponse
}

func NewCallableEvalResponse() *CallableEvalResponse {
	return &CallableEvalResponse{
		EvalResponse: &proto.EvalResponse{
			Status: proto.ExecutionStatus_SUCCESS,
			Result: &proto.AssessmentResult{
				Title:            "",
				Description:      "",
				Start:            nil,
				End:              nil,
				Props:            []*proto.Property{},
				Links:            []*proto.Link{},
				LocalDefinitions: nil,
				ReviewedControls: &proto.ReviewedControls{},
				Attestations:     []*proto.Attestation{},
				AssessmentLog: &proto.AssessmentLog{
					Entries: make([]*proto.AssessmentLog_Entry, 0),
				},
				Observations: []*proto.Observation{},
				Risks:        []*proto.Risk{},
				Findings:     []*proto.Finding{},
				Remarks:      nil,
			},
		},
	}
}

func (eval *CallableEvalResponse) AddObservation(observation *proto.Observation) {
	eval.GetResult().Observations = append(eval.GetResult().Observations, observation)
}

func (eval *CallableEvalResponse) AddFinding(finding *proto.Finding) {
	eval.GetResult().Findings = append(eval.GetResult().Findings, finding)
}

func (eval *CallableEvalResponse) AddLogEntry(logEntry *proto.AssessmentLog_Entry) {
	eval.GetResult().GetAssessmentLog().Entries = append(eval.GetResult().GetAssessmentLog().Entries, logEntry)
}

func (eval *CallableEvalResponse) AddRiskEntry(risk *proto.Risk) {
	eval.GetResult().Risks = append(eval.GetResult().Risks, risk)
}

func (eval *CallableEvalResponse) Result() *proto.EvalResponse {
	return eval.EvalResponse
}
