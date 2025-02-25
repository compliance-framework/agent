package runner

import "github.com/compliance-framework/agent/runner/proto"

// Constants used in plugins for statusses which map to OSCAL due to int requirements of GRPC
const (
	FindingTargetStatusSatisfied    = "satisfied"
	FindingTargetStatusNotSatisfied = "not satisfied"
)

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

type CallableAssessmentResult struct {
	*proto.AssessmentResult
}

func NewCallableAssessmentResult() *CallableAssessmentResult {
	return &CallableAssessmentResult{
		AssessmentResult: &proto.AssessmentResult{
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
	}
}

func (eval *CallableAssessmentResult) AddFinding(finding *proto.Finding) {
	eval.Findings = append(eval.Findings, finding)
}

func (eval *CallableAssessmentResult) AddObservation(observation *proto.Observation) {
	eval.Observations = append(eval.Observations, observation)
}

func (eval *CallableAssessmentResult) AddLogEntry(logEntry *proto.AssessmentLog_Entry) {
	eval.GetAssessmentLog().Entries = append(eval.GetAssessmentLog().Entries, logEntry)
}

func (eval *CallableAssessmentResult) AddRiskEntry(risk *proto.Risk) {
	eval.Risks = append(eval.Risks, risk)
}

func (eval *CallableAssessmentResult) Result() *proto.AssessmentResult {
	return eval.AssessmentResult
}
