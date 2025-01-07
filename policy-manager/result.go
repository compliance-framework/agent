package policy_manager

import (
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"strings"
)

type Violation struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remarks     string   `json:"remarks"`
	Controls    []string `json:"control-implementations"`
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
	Title       string `json:"title"`
}

type Activity struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Steps       []Step   `json:"steps"`
	Tools       []string `json:"tools"`
}

type Task struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Activities  []Activity
}

type Link struct {
	Text string `json:"text"`
	URL  string `json:"href"`
}

type Risk struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Statement   string `json:"statement"`
	Links       []Link `json:"links"`
}

type Result struct {
	Policy              Policy
	AdditionalVariables map[string]interface{}
	Violations          []Violation
	Tasks               []Task
	Risks               []Risk
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
