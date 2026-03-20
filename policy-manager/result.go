package policy_manager

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

type Violation struct {
	ID          *string `json:"id,omitempty" mapstructure:"id"`
	Title       *string `json:"title,omitempty" mapstructure:"title"`
	Description *string `json:"description,omitempty" mapstructure:"description"`
	Remarks     *string `json:"remarks,omitempty" mapstructure:"remarks"`
}

type Package string

func (p Package) PurePackage() string {
	return strings.TrimPrefix(string(p), "data.")
}

type Policy struct {
	File        string
	Package     Package
	Annotations []*ast.Annotations
}

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

type RiskTemplate struct {
	Name           string       `json:"name" mapstructure:"name"`
	Title          string       `json:"title" mapstructure:"title"`
	Statement      string       `json:"statement" mapstructure:"statement"`
	LikelihoodHint string       `json:"likelihood_hint" mapstructure:"likelihood_hint"`
	ImpactHint     string       `json:"impact_hint" mapstructure:"impact_hint"`
	ViolationIds   []string     `json:"violation_ids" mapstructure:"violation_ids"`
	ThreatRefs     []ThreatRef  `json:"threat_refs" mapstructure:"threat_refs"`
	Remediation    *Remediation `json:"remediation,omitempty" mapstructure:"remediation"`
}

type Result struct {
	Policy Policy
	*EvalOutput
}

func (res Result) String() string {
	return fmt.Sprintf(`
Policy:
	file: %s
	package: %s
	annotations: %s
AdditionalVariables: %v
Labels: %v
Violations: %v
`, res.Policy.File, res.Policy.Package.PurePackage(), res.Policy.Annotations, res.AdditionalVariables, res.Labels, res.Violations)
}
