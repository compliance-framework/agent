package runner

import (
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/uuid"
	"testing"
)

func TestCallableEvalResponse_AddFinding(t *testing.T) {
	resp := NewCallableEvalResponse()

	if len(resp.GetResult().Findings) > 0 {
		t.Errorf("len(resp.Findings): got %d, want %d", len(resp.GetResult().Findings), 0)
	}

	findingId := uuid.New().String()
	resp.AddFinding(&proto.Finding{
		Uuid:  findingId,
		Title: "A rather brilliant finding",
	})

	if len(resp.GetResult().Findings) != 1 {
		t.Errorf("len(resp.Findings): got %d, want %d", len(resp.GetResult().Findings), 1)
	}

	if resp.GetResult().Findings[0].Uuid != findingId {
		t.Errorf("resp.Findings[0].Id: got %s, want %s", resp.GetResult().Findings[0].Uuid, findingId)
	}
}

func TestCallableEvalResponse_AddObservation(t *testing.T) {
	resp := NewCallableEvalResponse()

	if len(resp.GetResult().Observations) > 0 {
		t.Errorf("len(resp.Findings): got %d, want %d", len(resp.GetResult().Observations), 0)
	}

	observationId := uuid.New().String()
	title := "Some clever observation"
	resp.AddObservation(&proto.Observation{
		Uuid:  observationId,
		Title: &title,
	})

	if len(resp.GetResult().Observations) != 1 {
		t.Errorf("len(resp.Findings): got %d, want %d", len(resp.GetResult().Observations), 1)
	}

	if resp.GetResult().Observations[0].Uuid != observationId {
		t.Errorf("resp.Findings[0].Id: got %s, want %s", resp.GetResult().Observations[0].Uuid, observationId)
	}
}

func TestCallableEvalResponse_AddLogEntry(t *testing.T) {
	resp := NewCallableEvalResponse()

	if len(resp.GetResult().AssessmentLog.Entries) > 0 {
		t.Errorf("len(resp.Findings): got %d, want %d", len(resp.GetResult().AssessmentLog.Entries), 0)
	}

	title := "Some Log"
	resp.AddLogEntry(&proto.AssessmentLog_Entry{
		Title: &title,
	})

	if len(resp.GetResult().AssessmentLog.Entries) != 1 {
		t.Errorf("len(resp.Findings): got %d, want %d", len(resp.GetResult().AssessmentLog.Entries), 1)
	}

	if *resp.GetResult().AssessmentLog.Entries[0].Title != "Some Log" {
		t.Errorf("resp.Findings[0].Id: got %s, want %s", *resp.GetResult().AssessmentLog.Entries[0].Title, "Some Log")
	}
}

func TestCallableEvalResponse_Result(t *testing.T) {
	resp := NewCallableEvalResponse()

	if resp.Result() != resp.EvalResponse {
		t.Errorf("resp.Result(): got %v, want %v", resp.Result(), resp.EvalResponse)
	}
}

func TestCallableAssessmentResult_AddFinding(t *testing.T) {
	result := NewCallableAssessmentResult()

	if len(result.Findings) > 0 {
		t.Errorf("len(result.Findings): got %d, want %d", len(result.Findings), 0)
	}

	findingId := uuid.New().String()
	result.AddFinding(&proto.Finding{
		Uuid:  findingId,
		Title: "A rather brilliant finding",
	})

	if len(result.Findings) != 1 {
		t.Errorf("len(result.Findings): got %d, want %d", len(result.Findings), 1)
	}

	if result.Findings[0].Uuid != findingId {
		t.Errorf("result.Findings[0].Id: got %s, want %s", result.Findings[0].Uuid, findingId)
	}
}

func TestCallableAssessmentResult_AddObservation(t *testing.T) {
	result := NewCallableAssessmentResult()

	if len(result.Observations) > 0 {
		t.Errorf("len(result.Findings): got %d, want %d", len(result.Observations), 0)
	}

	observationId := uuid.New().String()
	title := "Some clever observation"
	result.AddObservation(&proto.Observation{
		Uuid:  observationId,
		Title: &title,
	})

	if len(result.Observations) != 1 {
		t.Errorf("len(result.Findings): got %d, want %d", len(result.Observations), 1)
	}

	if result.Observations[0].Uuid != observationId {
		t.Errorf("result.Findings[0].Id: got %s, want %s", result.Observations[0].Uuid, observationId)
	}
}

func TestCallableAssessmentResult_AddLogEntry(t *testing.T) {
	result := NewCallableAssessmentResult()

	if len(result.AssessmentLog.Entries) > 0 {
		t.Errorf("len(result.Findings): got %d, want %d", len(result.AssessmentLog.Entries), 0)
	}

	title := "Some Log"
	result.AddLogEntry(&proto.AssessmentLog_Entry{
		Title: &title,
	})

	if len(result.AssessmentLog.Entries) != 1 {
		t.Errorf("len(result.Findings): got %d, want %d", len(result.AssessmentLog.Entries), 1)
	}

	if *result.AssessmentLog.Entries[0].Title != "Some Log" {
		t.Errorf("result.Findings[0].Id: got %s, want %s", *result.AssessmentLog.Entries[0].Title, "Some Log")
	}
}

func TestCallableAssessmentResult_AddRiskEntry(t *testing.T) {
  result := NewCallableAssessmentResult()

	if len(result.Risks) > 0 {
		t.Errorf("len(result.Findings): got %d, want %d", len(result.Risks), 0)
	}

	riskId := uuid.New().String()
	title := "Some risky business"
	result.AddRiskEntry(&proto.Risk{
		Uuid:  riskId,
		Title: title,
	})

	if len(result.Risks) != 1 {
		t.Errorf("len(result.Risks): got %d, want %d", len(result.Risks), 1)
	}

	if result.Risks[0].Title != "Some risky business" {
		t.Errorf("result.Risks[0].Id: got %s, want %s", result.Risks[0].Title, "Some risky business")
	}
}

func TestCallableAssessmentResult_Result(t *testing.T) {
	result := NewCallableAssessmentResult()

	if result.Result() != result.AssessmentResult {
		t.Errorf("result.Result(): got %v, want %v", result.Result(), result.AssessmentResult)
	}
}
