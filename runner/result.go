package runner

import "github.com/compliance-framework/agent/runner/proto"

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
