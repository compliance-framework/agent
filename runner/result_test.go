package runner

import (
	"testing"

	"github.com/compliance-framework/api/sdk/types"
)

func TestPrepareRiskTemplateForUpsertReturnsNilForNilInput(t *testing.T) {
	if got := prepareRiskTemplateForUpsert(nil); got != nil {
		t.Fatalf("expected nil risk template, got %#v", got)
	}
}

func TestPrepareRiskTemplateForUpsertHandlesNilRemediation(t *testing.T) {
	template := &types.RiskTemplate{
		ID:    "risk-template-id",
		Title: "Risk Template",
	}

	got := prepareRiskTemplateForUpsert(template)

	if got == nil {
		t.Fatal("expected risk template, got nil")
	}

	if got.Remediation != nil {
		t.Fatalf("expected remediation to stay nil, got %#v", got.Remediation)
	}

	if got.IsActive == nil || !*got.IsActive {
		t.Fatalf("expected IsActive to be true, got %#v", got.IsActive)
	}
}

func TestPrepareRiskTemplateForUpsertOrdersRemediationTasks(t *testing.T) {
	template := &types.RiskTemplate{
		ID: "risk-template-id",
		Remediation: &types.Remediation{
			Tasks: []types.RemediationTask{
				{Title: "Second", OrderIndex: 99},
				{Title: "Third", OrderIndex: 99},
				{Title: "Fourth", OrderIndex: 99},
			},
		},
	}

	got := prepareRiskTemplateForUpsert(template)

	if got == nil || got.Remediation == nil {
		t.Fatalf("expected remediation to be preserved, got %#v", got)
	}

	for i, task := range got.Remediation.Tasks {
		if task.OrderIndex != i {
			t.Fatalf("expected task %d to have order index %d, got %d", i, i, task.OrderIndex)
		}
	}
}

func TestWithPluginSelectorLabelReplacesExistingPluginLabel(t *testing.T) {
	labels := []types.SubjectTemplateSelectorLabel{
		{Key: "team", Value: "platform"},
		{Key: "_plugin", Value: "old-plugin"},
		{Key: "_plugin", Value: "stale-plugin"},
	}

	got := withPluginSelectorLabel(labels, "current-plugin")

	if len(got) != 2 {
		t.Fatalf("expected 2 selector labels after dedupe, got %d", len(got))
	}

	if got[0].Key != "team" || got[0].Value != "platform" {
		t.Fatalf("expected non-plugin selector label to be preserved, got %#v", got[0])
	}

	if got[1].Key != "_plugin" || got[1].Value != "current-plugin" {
		t.Fatalf("expected plugin selector label to be overwritten, got %#v", got[1])
	}
}

func TestWithPluginSelectorLabelAppendsWhenMissing(t *testing.T) {
	labels := []types.SubjectTemplateSelectorLabel{
		{Key: "team", Value: "platform"},
	}

	got := withPluginSelectorLabel(labels, "current-plugin")

	if len(got) != 2 {
		t.Fatalf("expected plugin selector label to be added, got %d labels", len(got))
	}

	if got[0].Key != "team" || got[0].Value != "platform" {
		t.Fatalf("expected existing selector label to be preserved, got %#v", got[0])
	}

	if got[1].Key != "_plugin" || got[1].Value != "current-plugin" {
		t.Fatalf("expected plugin selector label to be appended, got %#v", got[1])
	}
}
