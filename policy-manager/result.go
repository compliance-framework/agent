package policy_manager

import (
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"strings"
)

type Violation map[string]interface{}

func (v Violation) GetString(key string, defaultString string) string {
	if _, value := v[key]; value {
		return v[key].(string)
	}
	return defaultString
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

type Control struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type Result struct {
	Policy              Policy
	AdditionalVariables map[string]interface{}
	Violations          []Violation
	Controls            []Control
}

func (res Result) String() string {
	return fmt.Sprintf(`
Policy:
	file: %s
	package: %s
	annotations: %s
AdditionalVariables: %v
Violations: %s
Controls: %v
`, res.Policy.File, res.Policy.Package.PurePackage(), res.Policy.Annotations, res.AdditionalVariables, res.Violations, res.Controls)
}
