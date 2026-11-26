package internal

import (
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"gopkg.in/yaml.v3"
	"strings"
)

var RequiredAnnotations = []string{
	"title",
	"description",
	"controls",
}

// ExtractAnnotations takes comments from a rego file, and finds the metadata within.
// Metadata starts with a line `METADATA`, followed by a yaml document specifying the metadata for the specific policy.
// We use this to build a better picture of what the policy is used for, which controls it verifies, and who the
// responsible parties are.
func ExtractAnnotations(comments []*ast.Comment) map[string]interface{} {
	var metadataLines []string
	var metadataStarted = false

	previousLine := 0
	// Iterate over comments to find and collect metadata lines
	for _, comment := range comments {
		text := strings.TrimSpace(string(comment.Text))

		// Check if this line is the start of the metadata
		if text == "METADATA" {
			metadataStarted = true
			previousLine = comment.Location.Row
			continue
		}

		// If we're in the metadata section, collect lines
		if metadataStarted {
			// Break if we reach a blank line or a non-commented line
			if text == "" {
				break
			}

			// Break if the line is not directly after the previous one
			if comment.Location.Row != previousLine+1 {
				break
			}

			metadataLines = append(metadataLines, text)
			previousLine = comment.Location.Row
		}
	}

	// If no metadata lines were collected, return an empty map
	if len(metadataLines) == 0 {
		return map[string]interface{}{}
	}

	// Join metadata lines and parse them as YAML
	metadataYAML := strings.Join(metadataLines, "\n")
	metadata := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(metadataYAML), &metadata); err != nil {
		fmt.Printf("Failed to parse metadata: %v\n", err)
		return map[string]interface{}{}
	}

	return metadata
}
