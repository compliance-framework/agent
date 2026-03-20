package runner

import (
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
)

func TestRemediationProtoToSdkReturnsNilWhenProtoIsNil(t *testing.T) {
	if got := RemediationProtoToSdk(nil); got != nil {
		t.Fatalf("expected nil remediation, got %#v", got)
	}
}

func TestRiskTemplateProtoToSdkLeavesMissingRemediationNil(t *testing.T) {
	got := RiskTemplateProtoToSdk(&proto.RiskTemplate{
		UUID:  "risk-template-id",
		Name:  "risk-template",
		Title: "Risk Template",
	})

	if got == nil {
		t.Fatal("expected converted risk template, got nil")
	}

	if got.Remediation != nil {
		t.Fatalf("expected nil remediation, got %#v", got.Remediation)
	}
}

func TestRiskTemplateProtoToSdkConvertsRemediation(t *testing.T) {
	got := RiskTemplateProtoToSdk(&proto.RiskTemplate{
		UUID:  "risk-template-id",
		Name:  "risk-template",
		Title: "Risk Template",
		Remediation: &proto.Remediation{
			Title:       "Fix it",
			Description: "Do the thing",
			Tasks: []*proto.RemediationTask{
				{Title: "First task"},
				{Title: "Second task"},
			},
		},
	})

	if got == nil || got.Remediation == nil {
		t.Fatalf("expected converted remediation, got %#v", got)
	}

	if got.Remediation.Title != "Fix it" {
		t.Fatalf("expected remediation title %q, got %q", "Fix it", got.Remediation.Title)
	}

	if got.Remediation.Description == nil || *got.Remediation.Description != "Do the thing" {
		t.Fatalf("expected remediation description %q, got %#v", "Do the thing", got.Remediation.Description)
	}

	if len(got.Remediation.Tasks) != 2 {
		t.Fatalf("expected 2 remediation tasks, got %d", len(got.Remediation.Tasks))
	}
}
