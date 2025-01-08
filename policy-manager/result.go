package policy_manager

import (
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"strings"
)

type Violation struct {
	Title       string   `json:"title" mapstructure:"title"`
	Description string   `json:"description" mapstructure:"description"`
	Remarks     string   `json:"remarks" mapstructure:"remarks"`
	Controls    []string `json:"control-implementations" mapstructure:"control-implementations"`
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

type Task struct {
	Title       string     `json:"title" mapstructure:"title"`
	Description string     `json:"description" mapstructure:"description"`
	Activities  []Activity `json:"activities" mapstructure:"activities"`
}

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
Violations: %s
Tasks: %v
Risks: %v
`, res.Policy.File, res.Policy.Package.PurePackage(), res.Policy.Annotations, res.AdditionalVariables, res.Violations, res.Tasks, res.Risks)
}
