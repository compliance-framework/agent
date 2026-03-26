package runner

import (
	"slices"
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

func TestRiskTemplateProtoToSdkConvertsTemplateFieldsAndLabelSchema(t *testing.T) {
	got := RiskTemplateProtoToSdk(&proto.RiskTemplate{
		UUID:                   "risk-template-id",
		Name:                   "risk-template",
		Title:                  "Risk Template",
		TitleTemplate:          "Risk on {{ .subject }}",
		StatementTemplate:      "",
		LikelihoodHintTemplate: "{{ .likelihood }}",
		ImpactHintTemplate:     "",
		DedupeLabelKeys:        []string{"cluster", "hostname"},
		LabelSchema: []*proto.RiskTemplateLabelSchema{
			{
				Key:         "cluster",
				Description: "Cluster name",
			},
			{
				Key:         "hostname",
				Description: "Host name",
			},
		},
	})

	if got == nil {
		t.Fatal("expected converted risk template, got nil")
	}

	if got.TitleTemplate == nil || *got.TitleTemplate != "Risk on {{ .subject }}" {
		t.Fatalf("expected title template %q, got %#v", "Risk on {{ .subject }}", got.TitleTemplate)
	}

	if got.StatementTemplate != nil {
		t.Fatalf("expected nil statement template for empty string, got %#v", got.StatementTemplate)
	}

	if got.LikelihoodHintTemplate == nil || *got.LikelihoodHintTemplate != "{{ .likelihood }}" {
		t.Fatalf("expected likelihood hint template %q, got %#v", "{{ .likelihood }}", got.LikelihoodHintTemplate)
	}

	if got.ImpactHintTemplate != nil {
		t.Fatalf("expected nil impact hint template for empty string, got %#v", got.ImpactHintTemplate)
	}

	if !slices.Equal(got.DedupeLabelKeys, []string{"cluster", "hostname"}) {
		t.Fatalf("expected dedupe label keys %v, got %v", []string{"cluster", "hostname"}, got.DedupeLabelKeys)
	}

	if len(got.LabelSchema) != 2 {
		t.Fatalf("expected 2 label schema entries, got %d", len(got.LabelSchema))
	}

	if got.LabelSchema[0].Key != "cluster" {
		t.Fatalf("expected first label schema key %q, got %q", "cluster", got.LabelSchema[0].Key)
	}

	if got.LabelSchema[0].Description == nil || *got.LabelSchema[0].Description != "Cluster name" {
		t.Fatalf("expected first label schema description %q, got %#v", "Cluster name", got.LabelSchema[0].Description)
	}

	if got.LabelSchema[1].Key != "hostname" {
		t.Fatalf("expected second label schema key %q, got %q", "hostname", got.LabelSchema[1].Key)
	}

	if got.LabelSchema[1].Description == nil || *got.LabelSchema[1].Description != "Host name" {
		t.Fatalf("expected second label schema description %q, got %#v", "Host name", got.LabelSchema[1].Description)
	}
}
