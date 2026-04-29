package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/sdk"
	sdktypes "github.com/compliance-framework/api/sdk/types"
)

func TestSubmitEvidenceValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing labels fails",
			args:    []string{"Evidence", "--status", "satisfied", "--dry-run"},
			wantErr: "at least one --label or file label is required",
		},
		{
			name:    "missing status fails",
			args:    []string{"Evidence", "--label", "provider=gitlab", "--dry-run"},
			wantErr: "status is required",
		},
		{
			name:    "invalid status fails",
			args:    []string{"Evidence", "--status", "unknown", "--label", "provider=gitlab", "--dry-run"},
			wantErr: "status must be satisfied or not-satisfied",
		},
		{
			name:    "malformed label fails",
			args:    []string{"Evidence", "--status", "satisfied", "--label", "provider", "--dry-run"},
			wantErr: "label must be in key=value form",
		},
		{
			name:    "malformed link fails",
			args:    []string{"Evidence", "--status", "satisfied", "--label", "provider=gitlab", "--link", "Pipeline", "--dry-run"},
			wantErr: "link must be in text=href form",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := executeSubmitEvidenceCommand(t, tt.args, nil)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestSubmitEvidenceRejectsUUIDFromFile(t *testing.T) {
	t.Parallel()

	filePath := writeTempEvidenceFile(t, `
uuid: 123e4567-e89b-12d3-a456-426614174000
title: Evidence
labels:
  provider: gitlab
status:
  state: satisfied
`)

	_, err := executeSubmitEvidenceCommand(t, []string{"--file", filePath, "--dry-run"}, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "evidence file must not set uuid") {
		t.Fatalf("expected uuid rejection, got %q", err.Error())
	}
}

func TestSubmitEvidenceMergesFileAndFlags(t *testing.T) {
	t.Parallel()

	filePath := writeTempEvidenceFile(t, `
title: File title
description: file description
labels:
  provider: file
  file-only: keep
links:
  - text: File
    href: https://example.test/file
status:
  state: not-satisfied
  reason: file-reason
`)

	out, err := executeSubmitEvidenceCommand(t, []string{
		"--file", filePath,
		"CLI title",
		"--description", "CLI description",
		"--status", "satisfied",
		"--reason", "cli-reason",
		"--status-remarks", "status remarks",
		"--label", "provider=gitlab",
		"--label", "evidence-kind=pipeline-artifact",
		"--link", "Pipeline=https://example.test/pipeline",
		"--dry-run",
	}, nil)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}

	evidence := decodeEvidenceOutput(t, out)
	if evidence.Title != "CLI title" {
		t.Fatalf("expected CLI title, got %q", evidence.Title)
	}
	if evidence.Description != "CLI description" {
		t.Fatalf("expected CLI description, got %q", evidence.Description)
	}
	if evidence.Status.State != "satisfied" {
		t.Fatalf("expected CLI status, got %q", evidence.Status.State)
	}
	if evidence.Status.Reason != "cli-reason" {
		t.Fatalf("expected CLI reason, got %q", evidence.Status.Reason)
	}
	if evidence.Status.Remarks != "status remarks" {
		t.Fatalf("expected CLI status remarks, got %q", evidence.Status.Remarks)
	}
	if evidence.Labels["provider"] != "gitlab" {
		t.Fatalf("expected CLI label to override file label, got %q", evidence.Labels["provider"])
	}
	if evidence.Labels["file-only"] != "keep" {
		t.Fatalf("expected file-only label to be preserved")
	}
	if evidence.Labels["evidence-kind"] != "pipeline-artifact" {
		t.Fatalf("expected CLI label to be added")
	}
	if len(evidence.Links) != 2 {
		t.Fatalf("expected file and CLI links, got %d", len(evidence.Links))
	}
	if evidence.Links[1].Text != "Pipeline" || evidence.Links[1].Href != "https://example.test/pipeline" {
		t.Fatalf("unexpected CLI link: %#v", evidence.Links[1])
	}
}

func TestSubmitEvidenceFileTitleSatisfiesTitleRequirement(t *testing.T) {
	t.Parallel()

	filePath := writeTempEvidenceFile(t, `
title: File title
labels:
  provider: gitlab
status:
  state: satisfied
`)

	if _, err := executeSubmitEvidenceCommand(t, []string{"--file", filePath, "--dry-run"}, nil); err != nil {
		t.Fatalf("expected file title to satisfy title requirement: %v", err)
	}
}

func TestSubmitEvidenceUsesSeededUUIDFromAllLabels(t *testing.T) {
	t.Parallel()

	out, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--label", "evidence-kind=pipeline-artifact",
		"--dry-run",
	}, nil)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}

	evidence := decodeEvidenceOutput(t, out)
	expected, err := sdk.SeededUUID(map[string]string{
		"provider":      "gitlab",
		"evidence-kind": "pipeline-artifact",
	})
	if err != nil {
		t.Fatalf("seeded uuid: %v", err)
	}
	expectedReordered, err := sdk.SeededUUID(map[string]string{
		"evidence-kind": "pipeline-artifact",
		"provider":      "gitlab",
	})
	if err != nil {
		t.Fatalf("seeded uuid with reordered labels: %v", err)
	}
	changed, err := sdk.SeededUUID(map[string]string{
		"provider":      "gitlab",
		"evidence-kind": "different",
	})
	if err != nil {
		t.Fatalf("seeded uuid with changed label: %v", err)
	}

	if evidence.UUID != expected {
		t.Fatalf("expected command to use sdk.SeededUUID, got %s want %s", evidence.UUID, expected)
	}
	if expected != expectedReordered {
		t.Fatalf("expected SDK seeded UUID to be stable across label order")
	}
	if expected == changed {
		t.Fatalf("expected changing a label to change uuid")
	}
}

func TestSubmitEvidenceSubmitsWithAgentAuth(t *testing.T) {
	var tokenRequests int
	var evidenceRequests int
	var evidenceAuth string
	var submitted sdktypes.Evidence

	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenRequests++
			username, password, ok := r.BasicAuth()
			if !ok {
				t.Fatalf("expected basic auth on token request")
			}
			if username != "123e4567-e89b-12d3-a456-426614174000" || password != "client-secret" {
				t.Fatalf("unexpected basic auth credentials")
			}
			return jsonResponse(http.StatusOK, `{"access_token":"token-1","token_type":"bearer","expires_in":3600}`), nil
		case "/api/evidence":
			evidenceRequests++
			evidenceAuth = r.Header.Get("Authorization")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if err := json.Unmarshal(body, &submitted); err != nil {
				t.Fatalf("decode evidence: %v", err)
			}
			return jsonResponse(http.StatusCreated, ""), nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	t.Setenv("CCF_API_AUTH_CLIENT_ID", "123e4567-e89b-12d3-a456-426614174000")
	t.Setenv("CCF_API_AUTH_CLIENT_SECRET", "client-secret")

	_, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--api-url", "http://example.test",
		"--status", "satisfied",
		"--label", "provider=gitlab",
	}, client)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}
	if tokenRequests != 1 {
		t.Fatalf("expected one token request, got %d", tokenRequests)
	}
	if evidenceRequests != 1 {
		t.Fatalf("expected one evidence request, got %d", evidenceRequests)
	}
	if evidenceAuth != "Bearer token-1" {
		t.Fatalf("expected bearer auth, got %q", evidenceAuth)
	}
	if submitted.Title != "Evidence" {
		t.Fatalf("expected submitted evidence title, got %q", submitted.Title)
	}
	if submitted.Labels["provider"] != "gitlab" {
		t.Fatalf("expected submitted evidence labels, got %#v", submitted.Labels)
	}
}

func TestSubmitEvidenceRejectsPartialAgentAuth(t *testing.T) {
	t.Setenv("CCF_API_AUTH_CLIENT_ID", "123e4567-e89b-12d3-a456-426614174000")

	_, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--api-url", "http://example.test",
		"--status", "satisfied",
		"--label", "provider=gitlab",
	}, newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request")
		return nil, nil
	}))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "api auth requires both client_id and client_secret when configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSubmitEvidenceReturnsNonCreatedResponseError(t *testing.T) {
	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/evidence" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		return jsonResponse(http.StatusBadRequest, `{"error":"bad request"}`), nil
	})

	_, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--api-url", "http://example.test",
		"--status", "satisfied",
		"--label", "provider=gitlab",
	}, client)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unexpected api response status code: 400") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSubmitEvidenceUsesCommandContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		if err := r.Context().Err(); err != nil {
			return nil, err
		}
		t.Fatalf("expected request to use canceled command context")
		return nil, nil
	})

	_, err := executeSubmitEvidenceCommandWithContext(t, ctx, []string{
		"Evidence",
		"--api-url", "http://example.test",
		"--status", "satisfied",
		"--label", "provider=gitlab",
	}, client)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
}

func TestSubmitEvidenceExpiresAtRFC3339(t *testing.T) {
	t.Parallel()

	out, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "2027-04-29T12:00:00Z",
		"--dry-run",
	}, nil)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}

	evidence := decodeEvidenceOutput(t, out)
	expected := time.Date(2027, 4, 29, 12, 0, 0, 0, time.UTC)
	if !evidence.Expires.Equal(expected) {
		t.Fatalf("expected expires %v, got %v", expected, evidence.Expires)
	}
}

func TestSubmitEvidenceExpiresAtAfterYear(t *testing.T) {
	t.Parallel()

	out, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "@after 1year",
		"--dry-run",
	}, nil)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}

	evidence := decodeEvidenceOutput(t, out)
	expected := time.Date(2027, 4, 29, 12, 0, 0, 0, time.UTC) // 2026-04-29 + 1 year
	if !evidence.Expires.Equal(expected) {
		t.Fatalf("expected expires %v, got %v", expected, evidence.Expires)
	}
}

func TestSubmitEvidenceExpiresAtAfterYears(t *testing.T) {
	t.Parallel()

	out, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "@after 2years",
		"--dry-run",
	}, nil)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}

	evidence := decodeEvidenceOutput(t, out)
	expected := time.Date(2028, 4, 29, 12, 0, 0, 0, time.UTC) // 2026-04-29 + 2 years
	if !evidence.Expires.Equal(expected) {
		t.Fatalf("expected expires %v, got %v", expected, evidence.Expires)
	}
}

func TestSubmitEvidenceExpiresAtAfterMonth(t *testing.T) {
	t.Parallel()

	out, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "@after 3months",
		"--dry-run",
	}, nil)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}

	evidence := decodeEvidenceOutput(t, out)
	expected := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC) // 2026-04-29 + 3 months
	if !evidence.Expires.Equal(expected) {
		t.Fatalf("expected expires %v, got %v", expected, evidence.Expires)
	}
}

func TestSubmitEvidenceExpiresAtAfterDay(t *testing.T) {
	t.Parallel()

	out, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "@after 15days",
		"--dry-run",
	}, nil)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}

	evidence := decodeEvidenceOutput(t, out)
	expected := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC) // 2026-04-29 + 15 days
	if !evidence.Expires.Equal(expected) {
		t.Fatalf("expected expires %v, got %v", expected, evidence.Expires)
	}
}

func TestSubmitEvidenceExpiresAtAfterCombined(t *testing.T) {
	t.Parallel()

	out, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "@after 1year 2months 3days",
		"--dry-run",
	}, nil)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}

	evidence := decodeEvidenceOutput(t, out)
	expected := time.Date(2027, 7, 2, 12, 0, 0, 0, time.UTC) // 2026-04-29 + 1 year + 2 months + 3 days
	if !evidence.Expires.Equal(expected) {
		t.Fatalf("expected expires %v, got %v", expected, evidence.Expires)
	}
}

func TestSubmitEvidenceExpiresAtAfterCaseInsensitive(t *testing.T) {
	t.Parallel()

	out, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "@after 1YEAR 2MONTHS 3DAYS",
		"--dry-run",
	}, nil)
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}

	evidence := decodeEvidenceOutput(t, out)
	expected := time.Date(2027, 7, 2, 12, 0, 0, 0, time.UTC)
	if !evidence.Expires.Equal(expected) {
		t.Fatalf("expected expires %v, got %v", expected, evidence.Expires)
	}
}

func TestSubmitEvidenceExpiresAtAfterInvalidMissingDuration(t *testing.T) {
	t.Parallel()

	_, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "@after",
		"--dry-run",
	}, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "@after requires a duration") {
		t.Fatalf("expected @after requires duration error, got %q", err.Error())
	}
}

func TestSubmitEvidenceExpiresAtAfterInvalidUnknownUnit(t *testing.T) {
	t.Parallel()

	_, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "@after 5hours",
		"--dry-run",
	}, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unknown unit") {
		t.Fatalf("expected unknown unit error, got %q", err.Error())
	}
}

func TestSubmitEvidenceExpiresAtAfterInvalidMissingNumber(t *testing.T) {
	t.Parallel()

	_, err := executeSubmitEvidenceCommand(t, []string{
		"Evidence",
		"--status", "satisfied",
		"--label", "provider=gitlab",
		"--expires-at", "@after years",
		"--dry-run",
	}, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "expected number") {
		t.Fatalf("expected number parsing error, got %q", err.Error())
	}
}

func executeSubmitEvidenceCommand(t *testing.T, args []string, client *http.Client) (string, error) {
	t.Helper()

	return executeSubmitEvidenceCommandWithContext(t, context.Background(), args, client)
}

func executeSubmitEvidenceCommandWithContext(t *testing.T, ctx context.Context, args []string, client *http.Client) (string, error) {
	t.Helper()

	now := func() time.Time {
		return time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	}
	cmd := newSubmitEvidenceCmd(now, client)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	return out.String(), err
}

func writeTempEvidenceFile(t *testing.T, content string) string {
	t.Helper()

	filePath := t.TempDir() + "/evidence.yaml"
	if err := os.WriteFile(filePath, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("write evidence file: %v", err)
	}
	return filePath
}

func decodeEvidenceOutput(t *testing.T, out string) sdktypes.Evidence {
	t.Helper()

	var evidence sdktypes.Evidence
	if err := json.Unmarshal([]byte(out), &evidence); err != nil {
		t.Fatalf("decode evidence output: %v\n%s", err, out)
	}
	return evidence
}
