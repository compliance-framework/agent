package runner

import (
	"testing"

	"github.com/compliance-framework/api/sdk/types"
)

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
