package runner

import "github.com/compliance-framework/agent/runner/proto"

type Result struct {
	Status       proto.ExecutionStatus `json:"status"`
	AssessmentId string                `json:"assessmentId"`
	Error        error                 `json:"error"`
	Observations *[]*proto.Observation `json:"observations,omitempty"`
	Findings     *[]*proto.Finding     `json:"findings,omitempty"`
	Risks        *[]*proto.Risk        `json:"risks,omitempty"`
	Logs         *[]*proto.LogEntry    `json:"logs,omitempty"`
	StreamID     string                `json:"streamId"`
}

func ErrorResult(res *Result) *Result {
	res.Status = proto.ExecutionStatus_FAILURE
	return res
}
