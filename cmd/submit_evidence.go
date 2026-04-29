package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/compliance-framework/api/sdk"
	sdktypes "github.com/compliance-framework/api/sdk/types"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

type submitEvidenceOptions struct {
	filePath      string
	apiURL        string
	description   string
	remarks       string
	status        string
	reason        string
	statusRemarks string
	expiresAt     string
	labels        []string
	links         []string
	dryRun        bool
	now           func() time.Time
	httpClient    *http.Client
}

func SubmitEvidenceCmd() *cobra.Command {
	return newSubmitEvidenceCmd(time.Now, http.DefaultClient)
}

func newSubmitEvidenceCmd(now func() time.Time, httpClient *http.Client) *cobra.Command {
	opts := &submitEvidenceOptions{
		now:        now,
		httpClient: httpClient,
	}

	cmd := &cobra.Command{
		Use:   "submit-evidence [title]",
		Short: "submit a single evidence record to the Compliance Framework API",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSubmitEvidence(cmd, args, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.filePath, "file", "f", "", "YAML or JSON evidence file")
	cmd.Flags().StringVar(&opts.apiURL, "api-url", "", "Compliance Framework API URL")
	cmd.Flags().StringVar(&opts.description, "description", "", "Evidence description")
	cmd.Flags().StringVar(&opts.remarks, "remarks", "", "Evidence remarks")
	cmd.Flags().StringVar(&opts.status, "status", "", "Evidence status: satisfied or not-satisfied")
	cmd.Flags().StringVar(&opts.reason, "reason", "", "Status reason")
	cmd.Flags().StringVar(&opts.statusRemarks, "status-remarks", "", "Status remarks")
	cmd.Flags().StringVar(&opts.expiresAt, "expires-at", "", "Evidence expiry timestamp in RFC3339 format")
	cmd.Flags().StringArrayVar(&opts.labels, "label", nil, "Evidence label in key=value form; may be repeated")
	cmd.Flags().StringArrayVar(&opts.links, "link", nil, "Evidence link in text=href form; may be repeated")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "Print the final evidence JSON without submitting")

	return cmd
}

func runSubmitEvidence(cmd *cobra.Command, args []string, opts *submitEvidenceOptions) error {
	evidence, err := buildEvidence(cmd, args, opts)
	if err != nil {
		return err
	}

	if opts.dryRun {
		encoded, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
		return err
	}

	config, err := submitEvidenceConfig(opts.apiURL)
	if err != nil {
		return err
	}
	agentRunner := NewAgentRunner()
	agentRunner.httpClient = opts.httpClient
	agentRunner.UpdateConfig(config)

	return agentRunner.getAPIClient().Evidence.Create(context.Background(), evidence)
}

func buildEvidence(cmd *cobra.Command, args []string, opts *submitEvidenceOptions) (sdktypes.Evidence, error) {
	evidence := sdktypes.Evidence{}

	if strings.TrimSpace(opts.filePath) != "" {
		loaded, err := loadEvidenceFile(opts.filePath)
		if err != nil {
			return evidence, err
		}
		evidence = loaded
	}

	if len(args) > 0 {
		evidence.Title = args[0]
	}
	if strings.TrimSpace(evidence.Title) == "" {
		return evidence, fmt.Errorf("title is required when --file is not provided or the file does not set title")
	}

	flags := cmd.Flags()
	if flags.Changed("description") {
		evidence.Description = opts.description
	}
	if flags.Changed("remarks") {
		remarks := opts.remarks
		evidence.Remarks = &remarks
	}
	if flags.Changed("status") {
		evidence.Status.State = opts.status
	}
	if flags.Changed("reason") {
		evidence.Status.Reason = opts.reason
	}
	if flags.Changed("status-remarks") {
		evidence.Status.Remarks = opts.statusRemarks
	}
	if flags.Changed("expires-at") {
		expiresAt, err := parseRFC3339Flag("expires-at", opts.expiresAt)
		if err != nil {
			return evidence, err
		}
		evidence.Expires = &expiresAt
	}

	labels, err := parseLabels(opts.labels)
	if err != nil {
		return evidence, err
	}
	if len(labels) > 0 {
		if evidence.Labels == nil {
			evidence.Labels = map[string]string{}
		}
		for key, value := range labels {
			evidence.Labels[key] = value
		}
	}

	links, err := parseLinks(opts.links)
	if err != nil {
		return evidence, err
	}
	evidence.Links = append(evidence.Links, links...)

	if len(evidence.Labels) == 0 {
		return evidence, fmt.Errorf("at least one --label or file label is required")
	}
	if err := validateEvidenceStatus(evidence.Status.State); err != nil {
		return evidence, err
	}
	evidence.Status.State = strings.TrimSpace(evidence.Status.State)

	now := opts.now().UTC()
	if evidence.Start.IsZero() {
		evidence.Start = now
	}
	if evidence.End.IsZero() {
		evidence.End = now
	}

	evidenceUUID, err := sdk.SeededUUID(evidence.Labels)
	if err != nil {
		return evidence, err
	}
	evidence.UUID = evidenceUUID
	return evidence, nil
}

func loadEvidenceFile(path string) (sdktypes.Evidence, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return sdktypes.Evidence{}, err
	}

	jsonContent, err := yaml.YAMLToJSON(content)
	if err != nil {
		return sdktypes.Evidence{}, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(jsonContent, &raw); err != nil {
		return sdktypes.Evidence{}, err
	}
	for key := range raw {
		if strings.EqualFold(key, "uuid") {
			return sdktypes.Evidence{}, fmt.Errorf("evidence file must not set uuid; uuid is derived from labels")
		}
	}

	var evidence sdktypes.Evidence
	if err := json.Unmarshal(jsonContent, &evidence); err != nil {
		return sdktypes.Evidence{}, err
	}
	return evidence, nil
}

func parseLabels(values []string) (map[string]string, error) {
	labels := map[string]string{}
	for _, value := range values {
		key, labelValue, err := splitKeyValue(value, "label")
		if err != nil {
			return nil, err
		}
		labels[key] = labelValue
	}
	return labels, nil
}

func parseLinks(values []string) ([]sdktypes.Link, error) {
	links := make([]sdktypes.Link, 0, len(values))
	for _, value := range values {
		text, href, err := splitKeyValue(value, "link")
		if err != nil {
			return nil, err
		}
		links = append(links, sdktypes.Link{
			Text: text,
			Href: href,
		})
	}
	return links, nil
}

func splitKeyValue(value string, fieldName string) (string, string, error) {
	key, fieldValue, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(fieldValue) == "" {
		return "", "", fmt.Errorf("%s must be in key=value form", fieldName)
	}
	return strings.TrimSpace(key), strings.TrimSpace(fieldValue), nil
}

func validateEvidenceStatus(status string) error {
	switch strings.TrimSpace(status) {
	case "satisfied", "not-satisfied":
		return nil
	case "":
		return fmt.Errorf("status is required")
	default:
		return fmt.Errorf("status must be satisfied or not-satisfied")
	}
}

func parseRFC3339Flag(name string, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be an RFC3339 timestamp: %w", name, err)
	}
	return parsed.UTC(), nil
}

func submitEvidenceConfig(apiURLFlag string) (*agentConfig, error) {
	config := &agentConfig{
		ApiConfig: &apiConfig{
			Url: firstNonEmpty(apiURLFlag, os.Getenv("CCF_API_URL"), os.Getenv("INPUT_API_URL")),
			Auth: &apiAuthConfig{
				ClientID:     os.Getenv("CCF_API_AUTH_CLIENT_ID"),
				ClientSecret: os.Getenv("CCF_API_AUTH_CLIENT_SECRET"),
			},
		},
		Plugins: map[string]*agentPlugin{
			"submit-evidence": {
				Source: "submit-evidence",
			},
		},
	}
	if config.ApiConfig.Auth.ClientID == "" && config.ApiConfig.Auth.ClientSecret == "" {
		config.ApiConfig.Auth = nil
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return config, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
