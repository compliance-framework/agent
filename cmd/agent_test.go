package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type initTestRunner struct {
	initErr error
}

func (r *initTestRunner) Configure(request *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return &proto.ConfigureResponse{}, nil
}

func (r *initTestRunner) Eval(request *proto.EvalRequest, a runner.ApiHelper) (*proto.EvalResponse, error) {
	return &proto.EvalResponse{}, nil
}

func (r *initTestRunner) Init(request *proto.InitRequest, a runner.ApiHelper) (*proto.InitResponse, error) {
	return &proto.InitResponse{}, r.initErr
}

func TestAgentCmd_ConfigurationValidation(t *testing.T) {
	tests := []struct {
		name              string
		configYamlContent string
		valid             bool
	}{
		{
			name: "Valid Configuration",
			configYamlContent: `
api:
  url: http://localhost:8080

plugins:
  test-plugin:
    source: ghcr.io/some-plugin:v1
`,
			valid: true,
		},
		{
			name: "Valid Configuration With API Auth",
			configYamlContent: `
api:
  url: http://localhost:8080
  auth:
    client_id: test-client
    client_secret: test-secret

plugins:
  test-plugin:
    source: ghcr.io/some-plugin:v1
`,
			valid: true,
		},
		{
			name: "No API Configuration",
			configYamlContent: `
plugins:
  test-plugin:
    source: ghcr.io/some-plugin:v1
`,
			valid: false,
		},
		{
			name: "Rejects Partial API Auth",
			configYamlContent: `
api:
  url: http://localhost:8080
  auth:
    client_id: test-client

plugins:
  test-plugin:
    source: ghcr.io/some-plugin:v1
`,
			valid: false,
		},
		{
			name: "No Plugin Configuration",
			configYamlContent: `
api:
  url: http://localhost:8080
`,
			valid: false,
		},
		{
			name: "Unsupported Explicit Protocol Version",
			configYamlContent: `
api:
  url: http://localhost:8080

plugins:
  test-plugin:
    source: ghcr.io/some-plugin:v1
    protocol_version: 100
`,
			valid: false,
		},
		{
			name: "Null Plugin Configuration",
			configYamlContent: `
api:
  url: http://localhost:8080

plugins:
  test-plugin: null
`,
			valid: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			err := v.ReadConfig(bytes.NewBufferString(test.configYamlContent))
			if err != nil {
				t.Fatalf("Error reading config: %v", err)
			}

			config := &agentConfig{}
			err = v.Unmarshal(config)
			if err != nil {
				t.Fatalf("Error unmarshalling config: %v", err)
			}

			if err = config.validate(); (err == nil) != test.valid {
				t.Errorf("Expected validity of config to be %v, got %v", test.valid, err)
			}
		})
	}
}

func TestAgentCmd_ConfigurationMerging(t *testing.T) {
	for _, value := range []bool{true, false} {
		t.Run("Not setting daemon flag takes config value", func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			err := v.ReadConfig(bytes.NewBufferString(fmt.Sprintf(`daemon: %t`, value)))
			if err != nil {
				t.Fatalf("Error reading config: %v", err)
			}

			config, err := mergeConfig(AgentCmd(), v)
			if err != nil {
				t.Fatalf("Error merging config: %v", err)
			}

			if config.Daemon != value {
				t.Errorf("Expected config.Daemon to be %v, got %v", true, config.Daemon)
			}
		})
	}

	t.Run("Setting the daemon flag overrides the config file value", func(t *testing.T) {
		v := viper.New()
		v.SetConfigType("yaml")
		err := v.ReadConfig(bytes.NewBufferString(fmt.Sprintf(`daemon: %t`, false)))
		if err != nil {
			t.Fatalf("Error reading config: %v", err)
		}

		cmd := AgentCmd()
		// First, let's check that the config file value is used.
		config, err := mergeConfig(cmd, v)
		if err != nil {
			t.Fatalf("Error merging config: %v", err)
		}

		if config.Daemon != false {
			t.Errorf("Expected config.Daemon to be %v, got %v", true, config.Daemon)
		}

		// Now let's add the daemon flag for the CLI and see it overridden
		cmd.Flags().Set("daemon", "true")
		config, err = mergeConfig(cmd, v)
		if err != nil {
			t.Fatalf("Error merging config: %v", err)
		}
		if config.Daemon != true {
			t.Errorf("Expected config.Daemon to be %v, got %v", true, config.Daemon)
		}
	})
}

func TestMergeConfig_LoadsAPIAuthFromEnvironment(t *testing.T) {
	t.Setenv("CCF_API_AUTH_CLIENT_ID", "env-client-id")
	t.Setenv("CCF_API_AUTH_CLIENT_SECRET", "env-client-secret")

	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("CCF")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	err := v.ReadConfig(bytes.NewBufferString(`
api:
  url: http://localhost:8080

plugins:
  test-plugin:
    source: ghcr.io/some-plugin:v1
`))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	config, err := mergeConfig(AgentCmd(), v)
	if err != nil {
		t.Fatalf("Error merging config: %v", err)
	}

	if config.ApiConfig == nil || config.ApiConfig.Auth == nil {
		t.Fatalf("expected api auth config to be populated, got %#v", config.ApiConfig)
	}
	if got := config.ApiConfig.Auth.ClientID; got != "env-client-id" {
		t.Fatalf("expected client id from env, got %q", got)
	}
	if got := config.ApiConfig.Auth.ClientSecret; got != "env-client-secret" {
		t.Fatalf("expected client secret from env, got %q", got)
	}
}

func TestMergeConfig_DefaultsPluginProtocolVersion(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(bytes.NewBufferString("api:\n  url: http://localhost:8080\n\nplugins:\n  plugin-with-default:\n    source: ghcr.io/some-plugin:v1\n  plugin-with-explicit:\n    source: ghcr.io/some-plugin:v2\n    protocol_version: 2\n"))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	config, err := mergeConfig(AgentCmd(), v)
	if err != nil {
		t.Fatalf("Error merging config: %v", err)
	}

	if got := config.Plugins["plugin-with-default"].ProtocolVersion; got != 1 {
		t.Fatalf("Expected plugin-with-default protocol version to be 1, got %d", got)
	}

	if got := config.Plugins["plugin-with-explicit"].ProtocolVersion; got != 2 {
		t.Fatalf("Expected plugin-with-explicit protocol version to be 2, got %d", got)
	}
}

func TestUpdateAllPluginProtocols_DefaultsOnlyUnset(t *testing.T) {
	config := &agentConfig{
		Plugins: map[string]*agentPlugin{
			"defaulted": {
				Source: "ghcr.io/defaulted:v1",
			},
			"explicit": {
				Source:          "ghcr.io/explicit:v2",
				ProtocolVersion: 2,
				protocolSet:     true,
			},
			"explicit-zero": {
				Source:          "ghcr.io/explicit-zero:v1",
				ProtocolVersion: 0,
				protocolSet:     true,
			},
		},
	}

	updateAllPluginProtocols(config)

	if got := config.Plugins["defaulted"].ProtocolVersion; got != 1 {
		t.Fatalf("Expected defaulted plugin protocol version to be 1, got %d", got)
	}

	if got := config.Plugins["explicit"].ProtocolVersion; got != 2 {
		t.Fatalf("Expected explicit plugin protocol version to remain 2, got %d", got)
	}

	if got := config.Plugins["explicit-zero"].ProtocolVersion; got != 0 {
		t.Fatalf("Expected explicit-zero plugin protocol version to remain 0, got %d", got)
	}
}

func TestMergeConfig_RejectsUnsupportedExplicitProtocolVersion(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(bytes.NewBufferString("api:\n  url: http://localhost:8080\n\nplugins:\n  plugin-with-invalid-version:\n    source: ghcr.io/some-plugin:v1\n    protocol_version: 100\n"))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	config, err := mergeConfig(AgentCmd(), v)
	if err != nil {
		t.Fatalf("Error merging config: %v", err)
	}

	err = config.validate()
	if err == nil {
		t.Fatalf("Expected config validation to fail for unsupported protocol version")
	}

	expected := "plugin plugin-with-invalid-version has unsupported protocol_version=100; supported values are 1 and 2"
	if err.Error() != expected {
		t.Fatalf("Expected error %q, got %q", expected, err.Error())
	}
}

func TestMergeConfig_RejectsExplicitZeroProtocolVersion(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(bytes.NewBufferString("api:\n  url: http://localhost:8080\n\nplugins:\n  plugin-with-zero-version:\n    source: ghcr.io/some-plugin:v1\n    protocol_version: 0\n"))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	config, err := mergeConfig(AgentCmd(), v)
	if err != nil {
		t.Fatalf("Error merging config: %v", err)
	}

	err = config.validate()
	if err == nil {
		t.Fatalf("Expected config validation to fail for explicit zero protocol version")
	}

	expected := "plugin plugin-with-zero-version has unsupported protocol_version=0; supported values are 1 and 2"
	if err.Error() != expected {
		t.Fatalf("Expected error %q, got %q", expected, err.Error())
	}
}

func TestMergeConfig_RejectsNullPluginConfiguration(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(bytes.NewBufferString("api:\n  url: http://localhost:8080\n\nplugins:\n  null-plugin: null\n"))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	config, err := mergeConfig(AgentCmd(), v)
	if err != nil {
		t.Fatalf("Error merging config: %v", err)
	}

	err = config.validate()
	if err == nil {
		t.Fatalf("Expected config validation to fail for null plugin configuration")
	}

	expected := "plugin null-plugin has null configuration"
	if err.Error() != expected {
		t.Fatalf("Expected error %q, got %q", expected, err.Error())
	}
}

func TestMergeConfig_DoesNotFetchAnnotations(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(bytes.NewBufferString("api:\n  url: http://localhost:8080\n\nplugins:\n  plugin-with-default:\n    source: ghcr.io/some-plugin:v1\n"))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	config, err := mergeConfig(AgentCmd(), v)
	if err != nil {
		t.Fatalf("Error merging config: %v", err)
	}

	if got := config.Plugins["plugin-with-default"].ProtocolVersion; got != DefaultProtocolVersion {
		t.Fatalf("Expected plugin-with-default protocol version to be %d, got %d", DefaultProtocolVersion, got)
	}
}

func TestResolvePluginProtocols_UsesAnnotationsOnlyForImplicitOCIPlugins(t *testing.T) {
	lookupCount := 0
	ctx := context.Background()
	fetchAnnotations := func(fetchCtx context.Context, source string, option ...remote.Option) (map[string]string, error) {
		lookupCount++
		if fetchCtx == nil {
			t.Fatalf("expected fetchAnnotations context to be set")
		}
		return map[string]string{
			AnnotationProtocolVersionKey: "2",
		}, nil
	}

	config := &agentConfig{
		Plugins: map[string]*agentPlugin{
			"implicit-oci": {
				Source:          "ghcr.io/implicit:v1",
				ProtocolVersion: DefaultProtocolVersion,
				protocolSet:     false,
			},
			"explicit-v1": {
				Source:          "ghcr.io/explicit:v1",
				ProtocolVersion: DefaultProtocolVersion,
				protocolSet:     true,
			},
			"non-oci": {
				Source:          "/tmp/plugin",
				ProtocolVersion: DefaultProtocolVersion,
				protocolSet:     false,
			},
		},
	}

	runner := NewAgentRunner()
	runner.fetchAnnotations = fetchAnnotations
	runner.UpdateConfig(config)
	runner.resolvePluginProtocols(ctx)

	if lookupCount != 1 {
		t.Fatalf("Expected one annotation lookup, got %d", lookupCount)
	}

	if got := config.Plugins["implicit-oci"].ProtocolVersion; got != RunnerV2ProtocolVersion {
		t.Fatalf("Expected implicit-oci protocol version to be %d, got %d", RunnerV2ProtocolVersion, got)
	}

	if got := config.Plugins["explicit-v1"].ProtocolVersion; got != DefaultProtocolVersion {
		t.Fatalf("Expected explicit-v1 protocol version to remain %d, got %d", DefaultProtocolVersion, got)
	}

	if got := config.Plugins["non-oci"].ProtocolVersion; got != DefaultProtocolVersion {
		t.Fatalf("Expected non-oci protocol version to remain %d, got %d", DefaultProtocolVersion, got)
	}
}

func TestResolvePluginProtocols_KeepsDefaultWhenLookupFails(t *testing.T) {
	fetchAnnotations := func(fetchCtx context.Context, source string, option ...remote.Option) (map[string]string, error) {
		if fetchCtx == nil {
			t.Fatalf("expected fetchAnnotations context to be set")
		}
		return nil, errors.New("lookup failed")
	}

	config := &agentConfig{
		Plugins: map[string]*agentPlugin{
			"implicit-oci": {
				Source:          "ghcr.io/implicit:v1",
				ProtocolVersion: DefaultProtocolVersion,
				protocolSet:     false,
			},
		},
	}

	runner := NewAgentRunner()
	runner.fetchAnnotations = fetchAnnotations
	runner.UpdateConfig(config)
	runner.resolvePluginProtocols(context.Background())

	if got := config.Plugins["implicit-oci"].ProtocolVersion; got != DefaultProtocolVersion {
		t.Fatalf("Expected implicit-oci protocol version to remain %d, got %d", DefaultProtocolVersion, got)
	}
}

func TestProtocolVersionFromAnnotations(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		expected    int32
		ok          bool
	}{
		{
			name: "Uses OCI annotation key",
			annotations: map[string]string{
				AnnotationProtocolVersionKey: "2",
			},
			expected: 2,
			ok:       true,
		},
		{
			name: "Rejects unsupported values",
			annotations: map[string]string{
				AnnotationProtocolVersionKey: "100",
			},
			expected: 0,
			ok:       false,
		},
		{
			name: "Rejects invalid values",
			annotations: map[string]string{
				AnnotationProtocolVersionKey: "abc",
			},
			expected: 0,
			ok:       false,
		},
		{
			name: "Rejects non-positive values",
			annotations: map[string]string{
				AnnotationProtocolVersionKey: "0",
			},
			expected: 0,
			ok:       false,
		},
		{
			name:        "Missing keys",
			annotations: map[string]string{"other": "1"},
			expected:    0,
			ok:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := protocolVersionFromAnnotations(tt.annotations)
			if got != tt.expected || ok != tt.ok {
				t.Fatalf("protocolVersionFromAnnotations() = (%d, %t), expected (%d, %t)", got, ok, tt.expected, tt.ok)
			}
		})
	}
}

func TestRunnerDispenseName(t *testing.T) {
	tests := []struct {
		name            string
		protocolVersion int32
		expected        string
		wantErr         bool
	}{
		{
			name:            "Uses runner for v1",
			protocolVersion: DefaultProtocolVersion,
			expected:        "runner",
			wantErr:         false,
		},
		{
			name:            "Uses runner for v2",
			protocolVersion: RunnerV2ProtocolVersion,
			expected:        "runner",
			wantErr:         false,
		},
		{
			name:            "Rejects unsupported protocol version",
			protocolVersion: 3,
			expected:        "",
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := runnerDispenseName(tt.protocolVersion)
			if (err != nil) != tt.wantErr {
				t.Fatalf("runnerDispenseName() error = %v, wantErr %t", err, tt.wantErr)
			}

			if got != tt.expected {
				t.Fatalf("runnerDispenseName() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestInitRunner(t *testing.T) {
	t.Run("skips init for v1", func(t *testing.T) {
		err := initRunner("test-plugin", DefaultProtocolVersion, &initTestRunner{}, nil, nil)
		if err != nil {
			t.Fatalf("initRunner() error = %v, expected nil", err)
		}
	})

	t.Run("wraps unimplemented init for configured v2 plugin", func(t *testing.T) {
		err := initRunner(
			"test-plugin",
			RunnerV2ProtocolVersion,
			&initTestRunner{initErr: status.Error(codes.Unimplemented, "not implemented")},
			nil,
			nil,
		)
		if err == nil {
			t.Fatal("initRunner() error = nil, expected wrapped error")
		}

		expected := "plugin test-plugin configured as protocol_version=2 but does not implement Init"
		if err.Error() != expected {
			t.Fatalf("initRunner() error = %q, expected %q", err.Error(), expected)
		}
	})

	t.Run("passes through non-unimplemented init errors", func(t *testing.T) {
		expectedErr := errors.New("boom")
		err := initRunner(
			"test-plugin",
			RunnerV2ProtocolVersion,
			&initTestRunner{initErr: expectedErr},
			nil,
			nil,
		)
		if !errors.Is(err, expectedErr) {
			t.Fatalf("initRunner() error = %v, expected %v", err, expectedErr)
		}
	})
}

func TestAgentRunnerBuildsAuthenticatedSDKClient(t *testing.T) {
	var (
		tokenRequests   int
		protectedAuth   string
		tokenAuthHeader string
	)

	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenRequests++
			tokenAuthHeader = r.Header.Get("Authorization")
			return jsonResponse(http.StatusOK, `{"access_token":"token-1","token_type":"bearer","expires_in":3600}`), nil
		case "/api/test":
			protectedAuth = r.Header.Get("Authorization")
			return jsonResponse(http.StatusOK, ""), nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(newTestAgentConfig("http://example.test", &apiAuthConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}))

	resp, err := agentRunner.getAPIClient().NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_ = resp.Body.Close()

	if tokenRequests != 1 {
		t.Fatalf("expected one token request, got %d", tokenRequests)
	}
	if tokenAuthHeader == "" || !strings.HasPrefix(tokenAuthHeader, "Basic ") {
		t.Fatalf("expected token request to use basic auth, got %q", tokenAuthHeader)
	}
	if protectedAuth != "Bearer token-1" {
		t.Fatalf("expected protected request to use bearer auth, got %q", protectedAuth)
	}
}

func TestAgentRunnerBuildsUnauthenticatedSDKClientWhenAuthOmitted(t *testing.T) {
	var (
		tokenRequests int
		authHeader    string
	)

	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenRequests++
			t.Fatalf("unexpected token request without auth config")
			return nil, nil
		case "/api/test":
			authHeader = r.Header.Get("Authorization")
			return jsonResponse(http.StatusOK, ""), nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(newTestAgentConfig("http://example.test", nil))

	resp, err := agentRunner.getAPIClient().NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_ = resp.Body.Close()

	if tokenRequests != 0 {
		t.Fatalf("expected no token requests, got %d", tokenRequests)
	}
	if authHeader != "" {
		t.Fatalf("expected no authorization header, got %q", authHeader)
	}
}

func TestAgentRunnerUpdateConfigRebuildsSDKClient(t *testing.T) {
	agentRunner := NewAgentRunner()
	agentRunner.UpdateConfig(newTestAgentConfig("http://first.example", nil))
	firstClient := agentRunner.apiClient

	agentRunner.UpdateConfig(newTestAgentConfig("http://second.example", &apiAuthConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}))
	secondClient := agentRunner.apiClient

	if firstClient == nil || secondClient == nil {
		t.Fatalf("expected update config to build sdk clients, got first=%#v second=%#v", firstClient, secondClient)
	}
	if firstClient == secondClient {
		t.Fatal("expected update config to rebuild the shared sdk client")
	}
}

func TestSendHeartbeatUsesSDKHeartbeatClient(t *testing.T) {
	var (
		tokenRequests     int
		heartbeatRequests int
		heartbeatAuth     string
	)

	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenRequests++
			return jsonResponse(http.StatusOK, `{"access_token":"token-1","token_type":"bearer","expires_in":3600}`), nil
		case "/api/agent/heartbeat":
			heartbeatRequests++
			heartbeatAuth = r.Header.Get("Authorization")
			return jsonResponse(http.StatusCreated, ""), nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(newTestAgentConfig("http://example.test", &apiAuthConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}))

	if err := agentRunner.SendHeartbeat(context.Background(), uuid.New()); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	if tokenRequests != 1 {
		t.Fatalf("expected one token request, got %d", tokenRequests)
	}
	if heartbeatRequests != 1 {
		t.Fatalf("expected one heartbeat request, got %d", heartbeatRequests)
	}
	if heartbeatAuth != "Bearer token-1" {
		t.Fatalf("expected heartbeat request to use bearer auth, got %q", heartbeatAuth)
	}
}

func TestApiHelperUsesSharedSDKClientForProtectedWrites(t *testing.T) {
	var (
		tokenRequests int
		requestPaths  []string
		authHeaders   []string
	)

	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenRequests++
			return jsonResponse(http.StatusOK, `{"access_token":"token-1","token_type":"bearer","expires_in":3600}`), nil
		case "/api/evidence":
			requestPaths = append(requestPaths, r.URL.Path)
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			return jsonResponse(http.StatusCreated, ""), nil
		case "/api/agent/risk-templates/batch":
			requestPaths = append(requestPaths, r.URL.Path)
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			return jsonResponse(http.StatusOK, ""), nil
		case "/api/agent/subject-templates/batch":
			requestPaths = append(requestPaths, r.URL.Path)
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			return jsonResponse(http.StatusOK, ""), nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(newTestAgentConfig("http://example.test", &apiAuthConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}))

	apiHelper := runner.NewApiHelper(hclog.NewNullLogger(), agentRunner.getAPIClient(), map[string]string{
		"_agent": "agent-a",
	}, "plugin-a")

	now := time.Now().UTC()
	if err := apiHelper.CreateEvidence(context.Background(), []*proto.Evidence{
		{
			UUID:    uuid.NewString(),
			Title:   "Evidence",
			Start:   timestamppb.New(now.Add(-time.Hour)),
			End:     timestamppb.New(now.Add(-time.Minute)),
			Expires: timestamppb.New(now.Add(time.Hour)),
			Status: &proto.EvidenceStatus{
				Reason:  "pass",
				Remarks: "all good",
				State:   proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED,
			},
		},
	}); err != nil {
		t.Fatalf("create evidence: %v", err)
	}

	if err := apiHelper.UpsertRiskTemplates(context.Background(), "package-a", []*proto.RiskTemplate{
		{
			Name:      "risk-template",
			Title:     "Risk Template",
			Statement: "Risk statement",
		},
	}); err != nil {
		t.Fatalf("upsert risk templates: %v", err)
	}

	if err := apiHelper.UpsertSubjectTemplates(context.Background(), []*proto.SubjectTemplate{
		{
			Name:              "subject-template",
			Type:              proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			IdentityLabelKeys: []string{"asset_id"},
		},
	}); err != nil {
		t.Fatalf("upsert subject templates: %v", err)
	}

	expectedPaths := []string{
		"/api/evidence",
		"/api/agent/risk-templates/batch",
		"/api/agent/subject-templates/batch",
	}
	if tokenRequests != 1 {
		t.Fatalf("expected one token request for shared client, got %d", tokenRequests)
	}
	if len(requestPaths) != len(expectedPaths) {
		t.Fatalf("expected %d protected requests, got %d", len(expectedPaths), len(requestPaths))
	}
	for i, expectedPath := range expectedPaths {
		if requestPaths[i] != expectedPath {
			t.Fatalf("expected request %d path %q, got %q", i, expectedPath, requestPaths[i])
		}
		if authHeaders[i] != "Bearer token-1" {
			t.Fatalf("expected request %d to use bearer auth, got %q", i, authHeaders[i])
		}
	}
}

func newTestAgentConfig(baseURL string, auth *apiAuthConfig) *agentConfig {
	return &agentConfig{
		ApiConfig: &apiConfig{
			Url:  baseURL,
			Auth: auth,
		},
		Plugins: map[string]*agentPlugin{
			"test-plugin": {
				Source: "ghcr.io/some-plugin:v1",
			},
		},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestHTTPClient(handler roundTripFunc) *http.Client {
	return &http.Client{Transport: handler}
}

func jsonResponse(statusCode int, body string) *http.Response {
	if body == "" {
		body = "{}"
	}

	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
