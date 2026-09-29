package policy_manager

import (
	"github.com/compliance-framework/api/pkg/policyeval"
)

type Violation = policyeval.Violation

type Package = policyeval.Package

type Policy = policyeval.Policy

type Step struct {
	Title       string `json:"title" mapstructure:"title"`
	Description string `json:"description" mapstructure:"description"`
}

type Activity struct {
	Title       string   `json:"title" mapstructure:"title"`
	Description string   `json:"description" mapstructure:"description"`
	Type        string   `json:"type" mapstructure:"type"`
	Steps       []Step   `json:"steps" mapstructure:"steps"`
	Tools       []string `json:"tools" mapstructure:"tools"`
}

type Labels map[string]string

type Link struct {
	Text string `json:"text" mapstructure:"text"`
	URL  string `json:"href" mapstructure:"href"`
}

type Risk struct {
	Title       string `json:"title" mapstructure:"title"`
	Description string `json:"description" mapstructure:"description"`
	Statement   string `json:"statement" mapstructure:"statement"`
	Links       []Link `json:"links" mapstructure:"links"`
}

type ThreatRef struct {
	System     string `json:"system" mapstructure:"system"`
	ExternalID string `json:"external_id" mapstructure:"external_id"`
	Title      string `json:"title" mapstructure:"title"`
	Url        string `json:"url" mapstructure:"url"`
}
type RemediationTask struct {
	Title string `json:"title" mapstructure:"title"`
}

type Remediation struct {
	Title       string            `json:"title" mapstructure:"title"`
	Description string            `json:"description" mapstructure:"description"`
	Tasks       []RemediationTask `json:"tasks" mapstructure:"tasks"`
}

type RiskTemplateLabelSchema struct {
	Key         string `json:"key" mapstructure:"key"`
	Description string `json:"description" mapstructure:"description"`
}

type RiskTemplate struct {
	Name           string       `json:"name" mapstructure:"name"`
	Title          string       `json:"title" mapstructure:"title"`
	Statement      string       `json:"statement" mapstructure:"statement"`
	LikelihoodHint string       `json:"likelihood_hint" mapstructure:"likelihood_hint"`
	ImpactHint     string       `json:"impact_hint" mapstructure:"impact_hint"`
	ViolationIds   []string     `json:"violation_ids" mapstructure:"violation_ids"`
	ThreatRefs     []ThreatRef  `json:"threat_refs" mapstructure:"threat_refs"`
	Remediation    *Remediation `json:"remediation,omitempty" mapstructure:"remediation"`

	DedupeLabelKeys []string                  `json:"dedupe_label_keys" mapstructure:"dedupe_label_keys"`
	LabelSchema     []RiskTemplateLabelSchema `json:"label_schema" mapstructure:"label_schema"`
}

type Result = policyeval.Result
