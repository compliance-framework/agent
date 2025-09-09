package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// HttpCollectorConfig holds the configuration for the HTTP collector plugin
// This matches the config sample structure from the requirements
type HttpCollectorConfig struct {
	URL               string `json:"url"`
	Method            string `json:"method"`
	Timeout           int    `json:"timeout"`
	BasicAuth         bool   `json:"basic_auth"`
	BasicAuthUsername string `json:"basic_auth_username"`
	BasicAuthPassword string `json:"basic_auth_password"`
	AdditionalHeaders string `json:"additional_headers"`
	CheckCertificate  bool   `json:"check_certificate"`
	BodyRegexPattern  string `json:"body_regex_pattern"`
}

// HttpResponseData represents the structured response data
// This will be converted to JSON and included in evidence
type HttpResponseData struct {
	StatusCode       int                 `json:"status_code"`
	Status           string              `json:"status"`
	Headers          map[string][]string `json:"headers"`
	Body             string              `json:"body"`
	ResponseTime     int64               `json:"response_time_ms"`
	Success          bool                `json:"success"`                      // true if 200 <= status < 300
	Error            string              `json:"error,omitempty"`              // only if request failed
	MatchedRegex     bool                `json:"matched_regex,omitempty"`      // only if regex pattern provided
	BodyRegexPattern string              `json:"body_regex_pattern,omitempty"` // echo back the pattern used
}

// HttpCollectorPlugin implements the Runner interface
type HttpCollectorPlugin struct {
	logger hclog.Logger
	config *HttpCollectorConfig
}

// Configure implements runner.Runner
// This is called by the agent to provide configuration to the plugin
func (p *HttpCollectorPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	p.logger.Debug("Configuring HTTP collector plugin")

	// Initialize with defaults
	config := &HttpCollectorConfig{
		Method:           "GET",
		Timeout:          5000,
		CheckCertificate: true, // default to secure
	}

	// Parse configuration from the agent
	for key, value := range req.Config {
		switch key {
		case "url":
			config.URL = value
		case "method":
			config.Method = strings.ToUpper(value)
		case "timeout":
			if timeout, err := strconv.Atoi(value); err == nil {
				config.Timeout = timeout
			}
		case "basic_auth":
			// Handle various boolean representations
			lowerValue := strings.ToLower(value)
			config.BasicAuth = lowerValue == "true" || lowerValue == "1" || lowerValue == "yes"
		case "basic_auth_username":
			config.BasicAuthUsername = value
		case "basic_auth_password":
			config.BasicAuthPassword = value
		case "additional_headers":
			config.AdditionalHeaders = value
		case "check_certificate":
			config.CheckCertificate = strings.ToLower(value) != "false"
		case "body_regex_pattern":
			config.BodyRegexPattern = value
		}
	}

	// Validate required configuration
	if config.URL == "" {
		return nil, fmt.Errorf("url is required in configuration")
	}

	p.config = config
	p.logger.Info("HTTP collector configured successfully",
		"url", config.URL,
		"method", config.Method,
		"timeout", config.Timeout)

	return &proto.ConfigureResponse{}, nil
}

// makeHttpRequest performs the HTTP request and returns structured response data
func (p *HttpCollectorPlugin) makeHttpRequest() (*HttpResponseData, error) {
	startTime := time.Now()

	// Create HTTP client with timeout and TLS settings
	client := &http.Client{
		Timeout: time.Duration(p.config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !p.config.CheckCertificate,
			},
		},
	}

	// Create HTTP request
	req, err := http.NewRequest(p.config.Method, p.config.URL, nil)
	if err != nil {
		return &HttpResponseData{
			Success: false,
			Error:   fmt.Sprintf("failed to create request: %v", err),
		}, nil
	}

	// Add basic authentication if configured
	if p.config.BasicAuth && p.config.BasicAuthUsername != "" {
		req.SetBasicAuth(p.config.BasicAuthUsername, p.config.BasicAuthPassword)
		p.logger.Debug("Added basic authentication")
	}

	// Parse and add additional headers
	if p.config.AdditionalHeaders != "" {
		headers := strings.Split(p.config.AdditionalHeaders, ";")
		for _, header := range headers {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
		p.logger.Debug("Added additional headers", "count", len(headers))
	}

	// Execute the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return &HttpResponseData{
			Success:      false,
			Error:        fmt.Sprintf("HTTP request failed: %v", err),
			ResponseTime: time.Since(startTime).Milliseconds(),
		}, nil
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &HttpResponseData{
			Success:      false,
			Error:        fmt.Sprintf("failed to read response body: %v", err),
			StatusCode:   resp.StatusCode,
			Status:       resp.Status,
			Headers:      resp.Header,
			ResponseTime: time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Check if status code indicates success (200 <= x < 300)
	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	responseData := &HttpResponseData{
		StatusCode:   resp.StatusCode,
		Status:       resp.Status,
		Headers:      resp.Header,
		Body:         string(body),
		Success:      success,
		ResponseTime: time.Since(startTime).Milliseconds(),
	}

	// Check regex pattern if configured
	if p.config.BodyRegexPattern != "" {
		matched, err := regexp.MatchString(p.config.BodyRegexPattern, string(body))
		if err != nil {
			p.logger.Warn("Invalid regex pattern", "pattern", p.config.BodyRegexPattern, "error", err)
		} else {
			responseData.MatchedRegex = matched
			responseData.BodyRegexPattern = p.config.BodyRegexPattern
			p.logger.Debug("Regex pattern check", "pattern", p.config.BodyRegexPattern, "matched", matched)
		}
	}

	p.logger.Info("HTTP request completed",
		"status", resp.StatusCode,
		"success", success,
		"response_time_ms", responseData.ResponseTime)

	return responseData, nil
}

// createEvidence converts HTTP response data into Evidence protobuf for compliance reporting
func (p *HttpCollectorPlugin) createEvidence(responseData *HttpResponseData, jsonData string) (*proto.Evidence, error) {
	startTime := time.Now().Add(-time.Duration(responseData.ResponseTime) * time.Millisecond)
	endTime := time.Now()

	// Determine evidence status based on HTTP success and regex matching
	evidenceState := proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED
	statusReason := "HTTP request successful"

	if !responseData.Success {
		evidenceState = proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_NOT_SATISFIED
		if responseData.Error != "" {
			statusReason = fmt.Sprintf("HTTP request failed: %s", responseData.Error)
		} else {
			statusReason = fmt.Sprintf("HTTP request returned non-success status: %d %s", responseData.StatusCode, responseData.Status)
		}
	} else if responseData.BodyRegexPattern != "" && !responseData.MatchedRegex {
		evidenceState = proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_NOT_SATISFIED
		statusReason = fmt.Sprintf("Response body did not match required pattern: %s", responseData.BodyRegexPattern)
	}

	// Create evidence with comprehensive metadata
	description := fmt.Sprintf("HTTP %s request to %s", p.config.Method, p.config.URL)
	evidence := &proto.Evidence{
		UUID:        uuid.New().String(),
		Title:       "HTTP Endpoint Health Check",
		Description: &description,
		Start:       timestamppb.New(startTime),
		End:         timestamppb.New(endTime),
		Status: &proto.EvidenceStatus{
			State:   evidenceState,
			Reason:  statusReason,
			Remarks: jsonData, // Full JSON response data
		},
		Props: []*proto.Property{
			{Name: "http_url", Value: p.config.URL},
			{Name: "http_method", Value: p.config.Method},
			{Name: "status_code", Value: strconv.Itoa(responseData.StatusCode)},
			{Name: "response_time_ms", Value: strconv.FormatInt(responseData.ResponseTime, 10)},
			{Name: "success", Value: strconv.FormatBool(responseData.Success)},
		},
		Activities: []*proto.Activity{
			{
				Title:       "HTTP Health Check",
				Description: fmt.Sprintf("Performed %s request to %s for health monitoring", p.config.Method, p.config.URL),
				Steps: []*proto.Step{
					{
						Title: "Configure HTTP Client",
						Description: fmt.Sprintf("Set timeout: %dms, certificate check: %t, basic auth: %t",
							p.config.Timeout, p.config.CheckCertificate, p.config.BasicAuth),
					},
					{
						Title:       "Execute HTTP Request",
						Description: fmt.Sprintf("Made %s request to %s", p.config.Method, p.config.URL),
					},
					{
						Title: "Process Response",
						Description: fmt.Sprintf("Received status %d, processed %d bytes in %dms",
							responseData.StatusCode, len(responseData.Body), responseData.ResponseTime),
					},
				},
			},
		},
		Subjects: []*proto.Subject{
			{
				Identifier:  p.config.URL,
				Type:        proto.SubjectType_SUBJECT_TYPE_COMPONENT,
				Description: fmt.Sprintf("HTTP endpoint at %s", p.config.URL),
			},
		},
	}

	// Add regex-specific properties if configured
	if responseData.BodyRegexPattern != "" {
		evidence.Props = append(evidence.Props, &proto.Property{
			Name:  "regex_pattern",
			Value: responseData.BodyRegexPattern,
		})
		evidence.Props = append(evidence.Props, &proto.Property{
			Name:  "regex_matched",
			Value: strconv.FormatBool(responseData.MatchedRegex),
		})
	}

	return evidence, nil
}

// Eval implements runner.Runner
// This is the main execution function where we make HTTP requests and create evidence
func (p *HttpCollectorPlugin) Eval(req *proto.EvalRequest, helper runner.ApiHelper) (*proto.EvalResponse, error) {
	p.logger.Debug("Starting HTTP evaluation")

	// Make HTTP request
	responseData, err := p.makeHttpRequest()
	if err != nil {
		p.logger.Error("HTTP request failed", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	// Convert response data to JSON for evidence
	jsonData, err := json.MarshalIndent(responseData, "", "  ")
	if err != nil {
		p.logger.Error("Failed to marshal response data", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	// Create evidence from HTTP response
	evidence, err := p.createEvidence(responseData, string(jsonData))
	if err != nil {
		p.logger.Error("Failed to create evidence", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	// Send evidence to the compliance API via helper
	err = helper.CreateEvidence(context.Background(), []*proto.Evidence{evidence})
	if err != nil {
		p.logger.Error("Failed to send evidence", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	p.logger.Info("HTTP evaluation completed successfully", "success", responseData.Success)
	p.logger.Debug("Response data", "json", string(jsonData))

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func main() {
	// Create logger for the plugin
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "http-collector-plugin",
		Output: hclog.DefaultOutput,
		Level:  hclog.Debug,
	})

	// Serve the plugin using HashiCorp's plugin framework
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: &HttpCollectorPlugin{
					logger: logger,
				},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
