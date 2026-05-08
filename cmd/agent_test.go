package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type initTestRunner struct {
	initErr error
}

type emptyError struct{}

func (e emptyError) Error() string {
	return ""
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
    client_id: 123e4567-e89b-12d3-a456-426614174000
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
			name: "Rejects Missing API URL",
			configYamlContent: `
api:
  auth:
    client_id: 123e4567-e89b-12d3-a456-426614174000
    client_secret: test-secret

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
    client_id: 123e4567-e89b-12d3-a456-426614174000

plugins:
  test-plugin:
    source: ghcr.io/some-plugin:v1
`,
			valid: false,
		},
		{
			name: "Rejects Invalid API Auth Client ID",
			configYamlContent: `
api:
  url: http://localhost:8080
  auth:
    client_id: not-a-uuid
    client_secret: test-secret

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
			valid: true,
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
			markExplicitPluginProtocols(v, config)
			updateAllPluginProtocols(config)

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
	t.Setenv("CCF_API_AUTH_CLIENT_ID", "123e4567-e89b-12d3-a456-426614174000")
	t.Setenv("CCF_API_AUTH_CLIENT_SECRET", "env-client-secret")

	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("CCF")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := bindAgentEnv(v); err != nil {
		t.Fatalf("bind env: %v", err)
	}

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
	if got := config.ApiConfig.Auth.ClientID; got != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("expected client id from env, got %q", got)
	}
	if got := config.ApiConfig.Auth.ClientSecret; got != "env-client-secret" {
		t.Fatalf("expected client secret from env, got %q", got)
	}
}

func TestMergeConfig_ValidateFailsWhenAPIAuthEnvironmentIsPartial(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{
			name:     "client id only",
			clientID: "123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:         "client secret only",
			clientSecret: "env-client-secret",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.clientID != "" {
				t.Setenv("CCF_API_AUTH_CLIENT_ID", test.clientID)
			}
			if test.clientSecret != "" {
				t.Setenv("CCF_API_AUTH_CLIENT_SECRET", test.clientSecret)
			}

			v := viper.New()
			v.SetConfigType("yaml")
			v.SetEnvPrefix("CCF")
			v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
			v.AutomaticEnv()
			if err := bindAgentEnv(v); err != nil {
				t.Fatalf("bind env: %v", err)
			}

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

			err = config.validate()
			if err == nil {
				t.Fatal("expected validate to fail when only one api auth env var is set")
			}
			if err.Error() != "api auth requires both client_id and client_secret when configured" {
				t.Fatalf("expected validate error %q, got %q", "api auth requires both client_id and client_secret when configured", err.Error())
			}
		})
	}
}

func TestMaskClientID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		want     string
	}{
		{
			name:     "empty",
			clientID: "",
			want:     "",
		},
		{
			name:     "uuid",
			clientID: "123e4567-e89b-12d3-a456-426614174000",
			want:     "123e4567-...",
		},
		{
			name:     "trims whitespace",
			clientID: " 123e4567-e89b-12d3-a456-426614174000 ",
			want:     "123e4567-...",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := maskClientID(test.clientID); got != test.want {
				t.Fatalf("expected masked client id %q, got %q", test.want, got)
			}
		})
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

func TestSetupCronRunsDifferentPluginsIndependently(t *testing.T) {
	schedule := "@every 1s"
	ctx := context.Background()
	started := make(chan string, 2)
	release := make(chan struct{})

	agentRunner := NewAgentRunner()
	agentRunner.UpdateConfig(&agentConfig{
		Plugins: map[string]*agentPlugin{
			"plugin-a": {
				Source:   "/tmp/plugin-a",
				Schedule: &schedule,
			},
			"plugin-b": {
				Source:   "/tmp/plugin-b",
				Schedule: &schedule,
			},
		},
	})
	agentRunner.runPluginFunc = func(runCtx context.Context, name string, pluginConfig *agentPlugin) error {
		select {
		case started <- name:
		case <-runCtx.Done():
			return runCtx.Err()
		}

		select {
		case <-release:
			return nil
		case <-runCtx.Done():
			return runCtx.Err()
		}
	}

	agentCron, err := agentRunner.setupCron(ctx)
	if err != nil {
		t.Fatalf("setupCron() error = %v, expected nil", err)
	}

	agentCron.Start()
	defer func() {
		close(release)
		waitForTestCronStop(t, agentCron.Stop())
	}()

	first := waitForPluginStart(t, started)
	second := waitForPluginStart(t, started)
	if first == second {
		t.Fatalf("expected different plugins to start independently, got %q twice", first)
	}
}

func TestSetupCronSkipsRunsForSamePlugin(t *testing.T) {
	schedule := "@every 1s"
	ctx := context.Background()
	started := make(chan int, 2)
	releaseFirst := make(chan struct{})
	var logOutput bytes.Buffer
	releaseFirstIfNeeded := func() {
		select {
		case <-releaseFirst:
		default:
			close(releaseFirst)
		}
	}

	var runs int32
	agentRunner := NewAgentRunner()
	agentRunner.UpdateConfig(&agentConfig{
		Plugins: map[string]*agentPlugin{
			"plugin-a": {
				Source:   "/tmp/plugin-a",
				Schedule: &schedule,
			},
		},
	})
	agentRunner.stateMu.Lock()
	agentRunner.logger = hclog.New(&hclog.LoggerOptions{
		Name:   "agent-runner",
		Output: &logOutput,
		Level:  hclog.Info,
	})
	agentRunner.stateMu.Unlock()
	agentRunner.runPluginFunc = func(runCtx context.Context, name string, pluginConfig *agentPlugin) error {
		currentRun := int(atomic.AddInt32(&runs, 1))
		started <- currentRun

		if currentRun == 1 {
			select {
			case <-releaseFirst:
			case <-runCtx.Done():
				return runCtx.Err()
			}
		}

		return nil
	}

	agentCron, err := agentRunner.setupCron(ctx)
	if err != nil {
		t.Fatalf("setupCron() error = %v, expected nil", err)
	}

	agentCron.Start()
	stopped := false
	defer func() {
		releaseFirstIfNeeded()
		if !stopped {
			waitForTestCronStop(t, agentCron.Stop())
		}
	}()

	if got := waitForPluginRun(t, started); got != 1 {
		t.Fatalf("expected first plugin run to start first, got run %d", got)
	}

	select {
	case got := <-started:
		releaseFirstIfNeeded()
		t.Fatalf("expected second run to be skipped while the first was still running, but run %d started before release", got)
	case <-time.After(1500 * time.Millisecond):
	}

	releaseFirstIfNeeded()
	waitForTestCronStop(t, agentCron.Stop())
	stopped = true

	select {
	case got := <-started:
		t.Fatalf("expected no queued plugin run after first release, got run %d", got)
	default:
	}

	gotLogs := logOutput.String()
	if !strings.Contains(gotLogs, "skip") {
		t.Fatalf("expected skip log, got %q", gotLogs)
	}
	if !strings.Contains(gotLogs, "plugin-a") {
		t.Fatalf("expected skip log to include plugin name, got %q", gotLogs)
	}
}

func TestAgentRunnerTracksPluginClientCleanupPerRun(t *testing.T) {
	agentRunner := NewAgentRunner()
	agentRunner.logger = hclog.NewNullLogger()
	clientA := hplugin.NewClient(&hplugin.ClientConfig{})
	clientB := hplugin.NewClient(&hplugin.ClientConfig{})

	cleanupA := agentRunner.trackPluginClient(clientA)
	cleanupB := agentRunner.trackPluginClient(clientB)

	cleanupA()
	if got := activePluginClientCount(agentRunner); got != 1 {
		cleanupB()
		t.Fatalf("expected one active plugin client after cleaning up one run, got %d", got)
	}

	cleanupA()
	if got := activePluginClientCount(agentRunner); got != 1 {
		cleanupB()
		t.Fatalf("expected duplicate cleanup to be idempotent, got %d active clients", got)
	}

	cleanupB()
	if got := activePluginClientCount(agentRunner); got != 0 {
		t.Fatalf("expected all plugin clients to be cleaned up, got %d", got)
	}

	agentRunner.closePluginClients()
	clientAfterClose := hplugin.NewClient(&hplugin.ClientConfig{})
	cleanupAfterClose := agentRunner.trackPluginClient(clientAfterClose)
	defer cleanupAfterClose()
	if got := activePluginClientCount(agentRunner); got != 0 {
		t.Fatalf("expected plugin client tracked during cleanup to be killed immediately, got %d active clients", got)
	}
}

func TestWaitForCronStop(t *testing.T) {
	t.Run("returns true when all stop contexts finish", func(t *testing.T) {
		ctxA, cancelA := context.WithCancel(context.Background())
		ctxB, cancelB := context.WithCancel(context.Background())
		cancelA()
		cancelB()

		if !waitForCronStop(time.Second, ctxA, ctxB) {
			t.Fatal("expected waitForCronStop to return true when all contexts are done")
		}
	})

	t.Run("returns false on timeout", func(t *testing.T) {
		if waitForCronStop(10*time.Millisecond, context.Background()) {
			t.Fatal("expected waitForCronStop to return false when a context does not finish")
		}
	})
}

func waitForPluginStart(t *testing.T, started <-chan string) string {
	t.Helper()

	select {
	case name := <-started:
		return name
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for scheduled plugin to start")
		return ""
	}
}

func waitForPluginRun(t *testing.T, started <-chan int) int {
	t.Helper()

	select {
	case run := <-started:
		return run
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for scheduled plugin run to start")
		return 0
	}
}

func waitForTestCronStop(t *testing.T, stopCtx context.Context) {
	t.Helper()

	select {
	case <-stopCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for cron jobs to stop")
	}
}

func activePluginClientCount(agentRunner *AgentRunner) int {
	agentRunner.activePluginClientMu.Lock()
	defer agentRunner.activePluginClientMu.Unlock()
	return len(agentRunner.activePluginClients)
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
		ClientID:     "123e4567-e89b-12d3-a456-426614174000",
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

func TestAgentRunnerBuildsSDKClientWithTrimmedBaseURL(t *testing.T) {
	var requestPath string

	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		requestPath = r.URL.Path
		return jsonResponse(http.StatusOK, ""), nil
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(newTestAgentConfig("  http://example.test  ", nil))

	resp, err := agentRunner.getAPIClient().NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request with trimmed base url: %v", err)
	}
	_ = resp.Body.Close()

	if requestPath != "/api/test" {
		t.Fatalf("expected request path %q, got %q", "/api/test", requestPath)
	}
}

func TestAgentRunnerUpdateConfigRebuildsSDKClient(t *testing.T) {
	agentRunner := NewAgentRunner()
	agentRunner.UpdateConfig(newTestAgentConfig("http://first.example", nil))
	firstClient := agentRunner.apiClient

	agentRunner.UpdateConfig(newTestAgentConfig("http://second.example", &apiAuthConfig{
		ClientID:     "123e4567-e89b-12d3-a456-426614174000",
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
		ClientID:     "123e4567-e89b-12d3-a456-426614174000",
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
		ClientID:     "123e4567-e89b-12d3-a456-426614174000",
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

func TestAgentRunEvidenceIncludesPluginRunSummaryAndErrorArtifacts(t *testing.T) {
	t.Setenv("KUBERNETES_POD_NAME", "")
	t.Setenv("KUBERNETES_POD", "")

	interval := "30m"
	clientID := "123e4567-e89b-12d3-a456-426614174000"
	agentRunner := NewAgentRunner()
	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{
			Url: "http://example.test",
			Auth: &apiAuthConfig{
				ClientID:     clientID,
				ClientSecret: "client-secret",
			},
		},
		AgentEvidence: &agentEvidenceConfig{
			Interval: interval,
		},
		Plugins: map[string]*agentPlugin{
			"plugin-a": {Source: "/tmp/plugin-a"},
			"plugin-b": {Source: "/tmp/plugin-b"},
			"plugin-c": {Source: "/tmp/plugin-c"},
			"plugin-d": {Source: "/tmp/plugin-d"},
		},
	})

	agentRunner.markPluginRunStarted("plugin-a")
	agentRunner.markPluginRunFinished("plugin-a", nil)
	agentRunner.markPluginRunStarted("plugin-b")
	agentRunner.markPluginRunFinished("plugin-b", errors.New("collector failed"))
	agentRunner.markPluginRunStarted("plugin-c")

	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	evidence, err := agentRunner.buildAgentRunEvidence(now)
	if err != nil {
		t.Fatalf("build agent run evidence: %v", err)
	}

	if evidence.Status.State != "not-satisfied" {
		t.Fatalf("expected not-satisfied status, got %q", evidence.Status.State)
	}
	if evidence.Title != "CCF Agent is correctly capturing evidence" {
		t.Fatalf("expected self-evidence title, got %q", evidence.Title)
	}
	if evidence.Status.Reason != "CCF Agent could not collect evidence from one or more plugins." {
		t.Fatalf("expected readable failure reason, got %q", evidence.Status.Reason)
	}
	expectedLabels := map[string]string{
		"_agent":             clientID,
		agentConfigHashLabel: agentConfigurationHash(agentRunner.getConfig()),
		"tool":               "ccf",
		"type":               "operations",
	}
	for key, expected := range expectedLabels {
		if evidence.Labels[key] != expected {
			t.Fatalf("expected label %s=%q, got %q", key, expected, evidence.Labels[key])
		}
	}
	if len(evidence.Labels) != len(expectedLabels) {
		t.Fatalf("expected only foundational labels, got %#v", evidence.Labels)
	}
	if evidence.Expires == nil {
		t.Fatalf("expected evidence expiry")
	}
	expectedExpiry := now.Add(5 * 30 * time.Minute)
	if !evidence.Expires.Equal(expectedExpiry) {
		t.Fatalf("expected expiry %s, got %s", expectedExpiry, *evidence.Expires)
	}
	for _, expected := range []string{
		"Passing plugins: plugin-a",
		"Plugins with errors: plugin-b",
		"Pending plugins: plugin-d",
	} {
		if !strings.Contains(evidence.Description, expected) {
			t.Fatalf("expected description to contain %q, got %q", expected, evidence.Description)
		}
		if evidence.Remarks == nil || !strings.Contains(*evidence.Remarks, expected) {
			t.Fatalf("expected remarks to contain %q, got %v", expected, evidence.Remarks)
		}
	}
	if strings.Contains(evidence.Description, "Currently running plugins") {
		t.Fatalf("expected description to omit running plugins, got %q", evidence.Description)
	}
	if evidence.Remarks != nil && strings.Contains(*evidence.Remarks, "Currently running plugins") {
		t.Fatalf("expected remarks to omit running plugins, got %q", *evidence.Remarks)
	}
	if len(evidence.Links) != 1 {
		t.Fatalf("expected one error link, got %d", len(evidence.Links))
	}
	if evidence.Links[0].Href == "" || !strings.HasPrefix(evidence.Links[0].Href, "#") {
		t.Fatalf("expected backmatter link href, got %#v", evidence.Links[0])
	}
	if evidence.BackMatter == nil || evidence.BackMatter.Resources == nil || len(*evidence.BackMatter.Resources) != 1 {
		t.Fatalf("expected one backmatter resource, got %#v", evidence.BackMatter)
	}
	resource := (*evidence.BackMatter.Resources)[0]
	if resource.Base64 == nil {
		t.Fatalf("expected error resource base64 payload")
	}
	decoded, err := base64.StdEncoding.DecodeString(resource.Base64.Value)
	if err != nil {
		t.Fatalf("decode error resource: %v", err)
	}
	if string(decoded) != "collector failed" {
		t.Fatalf("expected plugin error in backmatter, got %q", string(decoded))
	}
}

func TestAgentRunEvidenceKeepsPluginErrorWhilePluginRunsAgainUntilPassing(t *testing.T) {
	t.Setenv("KUBERNETES_POD_NAME", "")
	t.Setenv("KUBERNETES_POD", "")

	var submittedDescription string
	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/evidence" {
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
		var submitted map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
			t.Fatalf("decode evidence request: %v", err)
		}
		submittedDescription, _ = submitted["description"].(string)
		return jsonResponse(http.StatusCreated, ""), nil
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
		Plugins: map[string]*agentPlugin{
			"plugin-x": {Source: "/tmp/plugin-x"},
		},
	})

	agentRunner.markPluginRunStarted("plugin-x")
	agentRunner.markPluginRunFinished("plugin-x", errors.New("first run failed"))
	agentRunner.markPluginRunStarted("plugin-x")

	evidenceBeforeSend, err := agentRunner.buildAgentRunEvidence(time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build agent run evidence before send: %v", err)
	}
	for _, expected := range []string{
		"Plugins with errors: plugin-x",
	} {
		if !strings.Contains(evidenceBeforeSend.Description, expected) {
			t.Fatalf("expected description to contain %q, got %q", expected, evidenceBeforeSend.Description)
		}
	}
	if strings.Contains(evidenceBeforeSend.Description, "Currently running plugins") {
		t.Fatalf("expected description to omit running plugins, got %q", evidenceBeforeSend.Description)
	}
	if evidenceBeforeSend.Status.State != "not-satisfied" {
		t.Fatalf("expected plugin error to fail evidence while rerunning, got %q", evidenceBeforeSend.Status.State)
	}
	if evidenceBeforeSend.BackMatter == nil {
		t.Fatalf("expected plugin error backmatter")
	}

	if err := agentRunner.SendAgentRunEvidence(context.Background()); err != nil {
		t.Fatalf("send agent run evidence: %v", err)
	}
	if !strings.Contains(submittedDescription, "Plugins with errors: plugin-x") {
		t.Fatalf("expected submitted evidence to include plugin error, got %q", submittedDescription)
	}

	evidenceAfterSend, err := agentRunner.buildAgentRunEvidence(time.Date(2026, 5, 7, 12, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build agent run evidence after send: %v", err)
	}
	if !strings.Contains(evidenceAfterSend.Description, "Plugins with errors: plugin-x") {
		t.Fatalf("expected evidence submission not to clear plugin error, got %q", evidenceAfterSend.Description)
	}
	if evidenceAfterSend.Status.State != "not-satisfied" {
		t.Fatalf("expected evidence to keep failing until plugin passes, got %q", evidenceAfterSend.Status.State)
	}

	agentRunner.markPluginRunFinished("plugin-x", nil)
	evidenceAfterPass, err := agentRunner.buildAgentRunEvidence(time.Date(2026, 5, 7, 12, 2, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build agent run evidence after pass: %v", err)
	}
	if !strings.Contains(evidenceAfterPass.Description, "Passing plugins: plugin-x") {
		t.Fatalf("expected passing plugin after successful finish, got %q", evidenceAfterPass.Description)
	}
	if !strings.Contains(evidenceAfterPass.Description, "Plugins with errors: none") {
		t.Fatalf("expected plugin error to clear after successful finish, got %q", evidenceAfterPass.Description)
	}
	if evidenceAfterPass.Status.State != "satisfied" {
		t.Fatalf("expected evidence to pass after plugin passes, got %q", evidenceAfterPass.Status.State)
	}
	if evidenceAfterPass.BackMatter != nil {
		t.Fatalf("expected no error backmatter after plugin passes, got %#v", evidenceAfterPass.BackMatter)
	}
}

func TestAgentRunEvidenceUsesEmissionTimeForStartAndEnd(t *testing.T) {
	agentRunner := NewAgentRunner()
	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
		Plugins: map[string]*agentPlugin{
			"plugin-x": {Source: "/tmp/plugin-x"},
		},
	})

	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	agentRunner.pluginRunMu.Lock()
	agentRunner.pluginRuns["plugin-x"] = pluginRunRecord{
		Status:    pluginRunStatusRunning,
		StartedAt: now.Add(time.Minute),
	}
	agentRunner.pluginRunMu.Unlock()

	evidence, err := agentRunner.buildAgentRunEvidence(now)
	if err != nil {
		t.Fatalf("build agent run evidence: %v", err)
	}
	if !evidence.Start.Equal(now) {
		t.Fatalf("expected start to use emission time %s, got %s", now, evidence.Start)
	}
	if !evidence.End.Equal(now) {
		t.Fatalf("expected end to use emission time %s, got %s", now, evidence.End)
	}
	if evidence.Start.After(evidence.End) {
		t.Fatalf("expected start not to be after end, got start=%s end=%s", evidence.Start, evidence.End)
	}
}

func TestAgentRunEvidenceStartupFailureRespectsRunCompletionConfig(t *testing.T) {
	var requests int32
	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&requests, 1)
		return jsonResponse(http.StatusCreated, ""), nil
	})

	emitOnRunCompletion := false
	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
		AgentEvidence: &agentEvidenceConfig{
			EmitOnRunCompletion: &emitOnRunCompletion,
		},
	})

	if err := agentRunner.sendAgentRunEvidenceOnStartupFailure(context.Background()); err != nil {
		t.Fatalf("send startup failure agent evidence: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("expected startup failure evidence to be gated off, got %d requests", got)
	}

	emitOnRunCompletion = true
	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
		AgentEvidence: &agentEvidenceConfig{
			EmitOnRunCompletion: &emitOnRunCompletion,
		},
	})
	if err := agentRunner.sendAgentRunEvidenceOnStartupFailure(context.Background()); err != nil {
		t.Fatalf("send enabled startup failure agent evidence: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected startup failure evidence to send when enabled, got %d requests", got)
	}
}

func TestReserveFirstAgentEvidenceRequiresConfiguredPluginRun(t *testing.T) {
	agentRunner := NewAgentRunner()
	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
		Plugins:   map[string]*agentPlugin{},
	})

	if agentRunner.reserveFirstAgentEvidenceSend() {
		t.Fatalf("expected no-plugin config not to reserve first complete run evidence")
	}

	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
		Plugins: map[string]*agentPlugin{
			"plugin-x": {Source: "/tmp/plugin-x"},
		},
	})
	if agentRunner.reserveFirstAgentEvidenceSend() {
		t.Fatalf("expected pending plugin not to reserve first complete run evidence")
	}

	agentRunner.markPluginRunStarted("plugin-x")
	agentRunner.markPluginRunFinished("plugin-x", nil)
	if !agentRunner.reserveFirstAgentEvidenceSend() {
		t.Fatalf("expected completed plugin run to reserve first complete run evidence")
	}
}

func TestAgentRunEvidenceTreatsEmptyErrorMessageAsPluginError(t *testing.T) {
	t.Setenv("KUBERNETES_POD_NAME", "")
	t.Setenv("KUBERNETES_POD", "")

	agentRunner := NewAgentRunner()
	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
		Plugins: map[string]*agentPlugin{
			"plugin-x": {Source: "/tmp/plugin-x"},
		},
	})

	agentRunner.markPluginRunStarted("plugin-x")
	agentRunner.markPluginRunFinished("plugin-x", emptyError{})

	evidence, err := agentRunner.buildAgentRunEvidence(time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build agent run evidence: %v", err)
	}
	if evidence.Status.State != "not-satisfied" {
		t.Fatalf("expected empty error message to fail evidence, got %q", evidence.Status.State)
	}
	if !strings.Contains(evidence.Description, "Plugins with errors: plugin-x") {
		t.Fatalf("expected plugin to be listed with errors, got %q", evidence.Description)
	}
	if evidence.BackMatter == nil || evidence.BackMatter.Resources == nil || len(*evidence.BackMatter.Resources) != 1 {
		t.Fatalf("expected fallback error backmatter, got %#v", evidence.BackMatter)
	}
	resource := (*evidence.BackMatter.Resources)[0]
	decoded, err := base64.StdEncoding.DecodeString(resource.Base64.Value)
	if err != nil {
		t.Fatalf("decode fallback error resource: %v", err)
	}
	if string(decoded) != "plugin run failed without an error message" {
		t.Fatalf("expected fallback error message, got %q", string(decoded))
	}
}

func TestAgentRunEvidenceTruncatesLargeErrorArtifacts(t *testing.T) {
	largeError := strings.Repeat("x", agentEvidenceErrorArtifactMaxBytes+1024)
	_, backMatter := agentEvidenceErrorArtifacts(map[string]string{
		"plugin-x": largeError,
	})

	if backMatter == nil || backMatter.Resources == nil || len(*backMatter.Resources) != 1 {
		t.Fatalf("expected one backmatter resource, got %#v", backMatter)
	}
	resource := (*backMatter.Resources)[0]
	if resource.Base64 == nil {
		t.Fatalf("expected base64 resource")
	}

	decoded, err := base64.StdEncoding.DecodeString(resource.Base64.Value)
	if err != nil {
		t.Fatalf("decode truncated error resource: %v", err)
	}
	if len(decoded) > agentEvidenceErrorArtifactMaxBytes {
		t.Fatalf("expected decoded error artifact to be at most %d bytes, got %d", agentEvidenceErrorArtifactMaxBytes, len(decoded))
	}
	if !strings.Contains(string(decoded), "[truncated: plugin error exceeded") {
		t.Fatalf("expected truncation marker, got %q", string(decoded[len(decoded)-80:]))
	}
}

func TestSendAgentRunEvidenceAllowsNoPlugins(t *testing.T) {
	t.Setenv("KUBERNETES_POD_NAME", "")
	t.Setenv("KUBERNETES_POD", "")

	var submitted map[string]interface{}
	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/evidence" {
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
		if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
			t.Fatalf("decode evidence request: %v", err)
		}
		return jsonResponse(http.StatusCreated, ""), nil
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
		Plugins:   map[string]*agentPlugin{},
	})

	if err := agentRunner.SendAgentRunEvidence(context.Background()); err != nil {
		t.Fatalf("send agent run evidence: %v", err)
	}

	status, ok := submitted["status"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected status object, got %#v", submitted["status"])
	}
	if status["state"] != "satisfied" {
		t.Fatalf("expected satisfied status, got %#v", status)
	}
	if status["reason"] != "CCF Agent is capturing evidence correctly." {
		t.Fatalf("expected readable passing reason, got %#v", status)
	}
	labels, ok := submitted["labels"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected labels object, got %#v", submitted["labels"])
	}
	if labels["_agent"] != "ccf" || labels["tool"] != "ccf" || labels["type"] != "operations" {
		t.Fatalf("unexpected foundational labels: %#v", labels)
	}
	if labels[agentConfigHashLabel] != agentConfigurationHash(agentRunner.getConfig()) {
		t.Fatalf("expected agent config hash label, got %#v", labels)
	}
	if len(labels) != 4 {
		t.Fatalf("expected only four foundational labels, got %#v", labels)
	}
	if _, ok := submitted["back-matter"]; ok {
		t.Fatalf("expected no backmatter for passing no-plugin evidence, got %#v", submitted["back-matter"])
	}
	description, _ := submitted["description"].(string)
	if !strings.Contains(description, "Passing plugins: none") {
		t.Fatalf("expected no-plugin summary, got %q", description)
	}
}

func TestSendAgentRunEvidenceIncludesAPIErrorBody(t *testing.T) {
	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/evidence" {
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
		return jsonResponse(http.StatusBadRequest, `{"error":"bad evidence"}`), nil
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
		Plugins:   map[string]*agentPlugin{},
	})

	err := agentRunner.SendAgentRunEvidence(context.Background())
	if err == nil {
		t.Fatalf("expected send agent run evidence to fail")
	}
	if !strings.Contains(err.Error(), "unexpected api response status code: 400") {
		t.Fatalf("expected status code in error, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), `{"error":"bad evidence"}`) {
		t.Fatalf("expected response body in error, got %q", err.Error())
	}
}

func TestAgentIdentityLabelFallsBackToKubernetesPodName(t *testing.T) {
	t.Setenv("KUBERNETES_POD_NAME", "ccf-agent-7b6f")
	t.Setenv("KUBERNETES_POD", "ignored")

	got := agentIdentityLabel(&agentConfig{
		ApiConfig: &apiConfig{Url: "http://example.test"},
	})
	if got != "ccf-agent-7b6f" {
		t.Fatalf("expected Kubernetes pod name identity, got %q", got)
	}

	got = agentIdentityLabel(&agentConfig{
		ApiConfig: &apiConfig{
			Url: "http://example.test",
			Auth: &apiAuthConfig{
				ClientID: "123e4567-e89b-12d3-a456-426614174000",
			},
		},
	})
	if got != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("expected API auth client id to take precedence, got %q", got)
	}
}

func TestAgentConfigurationHashUsesRuntimeConfigOnly(t *testing.T) {
	base := newRuntimeHashTestConfig()
	baseHash := agentConfigurationHash(base)
	if len(baseHash) != 64 {
		t.Fatalf("expected sha256 hex hash, got %q", baseHash)
	}

	reordered := newRuntimeHashTestConfigWithReorderedPlugins()
	reordered.ApiConfig = &apiConfig{
		Url: "http://different.example.test",
		Auth: &apiAuthConfig{
			ClientID:     "123e4567-e89b-12d3-a456-426614174000",
			ClientSecret: "different-secret",
		},
	}
	reordered.Verbosity = 3
	reordered.Daemon = !base.Daemon
	reordered.Plugins["plugin-a"].Policies = []agentPolicy{"policy-b", "policy-a", "policy-b"}
	reordered.Plugins["plugin-a"].Config = agentPluginConfig{
		"token":  "different-secret-token",
		"region": "different-region",
	}
	if got := agentConfigurationHash(reordered); got != baseHash {
		t.Fatalf("expected reordered plugins, reordered policies, and excluded fields to keep hash stable, got %q want %q", got, baseHash)
	}

	tests := []struct {
		name   string
		mutate func(*agentConfig)
	}{
		{
			name: "plugin source",
			mutate: func(config *agentConfig) {
				config.Plugins["plugin-a"].Source = "ghcr.io/example/plugin-a:v2"
			},
		},
		{
			name: "plugin schedule",
			mutate: func(config *agentConfig) {
				schedule := "0 * * * *"
				config.Plugins["plugin-a"].Schedule = &schedule
			},
		},
		{
			name: "plugin policy",
			mutate: func(config *agentConfig) {
				config.Plugins["plugin-a"].Policies = append(config.Plugins["plugin-a"].Policies, "policy-c")
			},
		},
		{
			name: "plugin config key",
			mutate: func(config *agentConfig) {
				config.Plugins["plugin-a"].Config["account_id"] = "123456789012"
			},
		},
		{
			name: "plugin label",
			mutate: func(config *agentConfig) {
				config.Plugins["plugin-a"].Labels["environment"] = "prod"
			},
		},
		{
			name: "protocol version",
			mutate: func(config *agentConfig) {
				config.Plugins["plugin-a"].ProtocolVersion = RunnerV2ProtocolVersion
			},
		},
		{
			name: "agent evidence interval",
			mutate: func(config *agentConfig) {
				config.AgentEvidence.Interval = "2h"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := newRuntimeHashTestConfig()
			tt.mutate(config)
			if got := agentConfigurationHash(config); got == baseHash {
				t.Fatalf("expected %s change to alter hash %q", tt.name, got)
			}
		})
	}
}

func TestAgentConfigurationHashExcludesPluginConfigValues(t *testing.T) {
	base := newRuntimeHashTestConfig()
	changedSecret := newRuntimeHashTestConfig()
	changedSecret.Plugins["plugin-a"].Config["token"] = "different-secret-token"
	changedSecret.Plugins["plugin-a"].Config["region"] = "eu-west-1"

	if got, want := agentConfigurationHash(changedSecret), agentConfigurationHash(base); got != want {
		t.Fatalf("expected plugin config value changes to be excluded from hash, got %q want %q", got, want)
	}
}

func TestAgentFoundationalLabelsIncludeAgentConfigurationHash(t *testing.T) {
	config := newRuntimeHashTestConfig()

	labels := agentFoundationalLabels(config)

	if labels[agentConfigHashLabel] != agentConfigurationHash(config) {
		t.Fatalf("expected foundational labels to include config hash, got %#v", labels)
	}
}

func TestAgentRunEvidenceUUIDUsesAgentConfigurationHash(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	firstRunner := NewAgentRunner()
	firstRunner.UpdateConfig(newRuntimeHashTestConfig())
	firstEvidence, err := firstRunner.buildAgentRunEvidence(now)
	if err != nil {
		t.Fatalf("build first agent run evidence: %v", err)
	}

	secondConfig := newRuntimeHashTestConfig()
	secondConfig.Plugins["plugin-a"].Source = "ghcr.io/example/plugin-a:v2"
	secondRunner := NewAgentRunner()
	secondRunner.UpdateConfig(secondConfig)
	secondEvidence, err := secondRunner.buildAgentRunEvidence(now)
	if err != nil {
		t.Fatalf("build second agent run evidence: %v", err)
	}

	if firstEvidence.Labels[agentConfigHashLabel] == secondEvidence.Labels[agentConfigHashLabel] {
		t.Fatalf("expected different config hash labels, got %q", firstEvidence.Labels[agentConfigHashLabel])
	}
	if firstEvidence.UUID == secondEvidence.UUID {
		t.Fatalf("expected config hash change to alter agent evidence UUID %s", firstEvidence.UUID)
	}
}

func TestPluginEvidenceLabelsIncludeAgentConfigurationHash(t *testing.T) {
	config := newRuntimeHashTestConfig()

	labels := pluginEvidenceLabels(config, "plugin-a", config.Plugins["plugin-a"])

	if labels[agentConfigHashLabel] != agentConfigurationHash(config) {
		t.Fatalf("expected plugin labels to include config hash, got %#v", labels)
	}
	if labels["_plugin"] != "plugin-a" {
		t.Fatalf("expected plugin label, got %#v", labels)
	}
	if labels["team"] != "security" {
		t.Fatalf("expected configured plugin labels to be preserved, got %#v", labels)
	}
}

func TestPluginEvidenceSubmissionIncludesAgentConfigurationHash(t *testing.T) {
	config := newRuntimeHashTestConfig()
	config.ApiConfig.Auth = nil
	var submittedLabels map[string]string
	var submittedUUID uuid.UUID
	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/evidence" {
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
		var submitted struct {
			Labels map[string]string `json:"labels"`
			UUID   uuid.UUID         `json:"uuid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
			t.Fatalf("decode evidence request: %v", err)
		}
		submittedLabels = submitted.Labels
		submittedUUID = submitted.UUID
		return jsonResponse(http.StatusCreated, ""), nil
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(config)
	apiHelper := runner.NewApiHelper(
		hclog.NewNullLogger(),
		agentRunner.getAPIClient(),
		pluginEvidenceLabels(config, "plugin-a", config.Plugins["plugin-a"]),
		"plugin-a",
	)

	now := time.Now().UTC()
	if err := apiHelper.CreateEvidence(context.Background(), []*proto.Evidence{
		{
			UUID:  uuid.NewString(),
			Title: "Evidence",
			Start: timestamppb.New(now.Add(-time.Minute)),
			End:   timestamppb.New(now),
			Status: &proto.EvidenceStatus{
				Reason: "pass",
				State:  proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED,
			},
		},
	}); err != nil {
		t.Fatalf("create evidence: %v", err)
	}

	if submittedLabels[agentConfigHashLabel] != agentConfigurationHash(config) {
		t.Fatalf("expected submitted plugin evidence to include config hash, got %#v", submittedLabels)
	}
	if submittedLabels["_plugin"] != "plugin-a" || submittedLabels["team"] != "security" {
		t.Fatalf("expected submitted plugin evidence to include plugin labels, got %#v", submittedLabels)
	}
	expectedUUID, err := sdk.SeededUUID(submittedLabels)
	if err != nil {
		t.Fatalf("seed expected UUID: %v", err)
	}
	if submittedUUID != expectedUUID {
		t.Fatalf("expected submitted plugin evidence UUID to be seeded from merged labels, got %s want %s", submittedUUID, expectedUUID)
	}
}

func TestPluginProvidedEvidenceLabelsCannotOverrideReservedAgentLabels(t *testing.T) {
	config := newRuntimeHashTestConfig()
	config.ApiConfig.Auth = nil
	var submittedLabels map[string]string
	client := newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/evidence" {
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
		var submitted struct {
			Labels map[string]string `json:"labels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
			t.Fatalf("decode evidence request: %v", err)
		}
		submittedLabels = submitted.Labels
		return jsonResponse(http.StatusCreated, ""), nil
	})

	agentRunner := NewAgentRunner()
	agentRunner.httpClient = client
	agentRunner.UpdateConfig(config)
	apiHelper := runner.NewApiHelper(
		hclog.NewNullLogger(),
		agentRunner.getAPIClient(),
		pluginEvidenceLabels(config, "plugin-a", config.Plugins["plugin-a"]),
		"plugin-a",
	)

	now := time.Now().UTC()
	if err := apiHelper.CreateEvidence(context.Background(), []*proto.Evidence{
		{
			UUID:  uuid.NewString(),
			Title: "Evidence",
			Labels: map[string]string{
				agentConfigHashLabel: "plugin-provided-hash",
				"_agent":             "plugin-provided-agent",
				"_plugin":            "plugin-provided-plugin",
			},
			Start: timestamppb.New(now.Add(-time.Minute)),
			End:   timestamppb.New(now),
			Status: &proto.EvidenceStatus{
				Reason: "pass",
				State:  proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED,
			},
		},
	}); err != nil {
		t.Fatalf("create evidence: %v", err)
	}

	if submittedLabels[agentConfigHashLabel] != agentConfigurationHash(config) {
		t.Fatalf("expected agent config hash label to be reserved, got %#v", submittedLabels)
	}
	if submittedLabels["_agent"] != "ccf" || submittedLabels["_plugin"] != "plugin-a" {
		t.Fatalf("expected reserved agent labels to be preserved, got %#v", submittedLabels)
	}
}

func TestAgentEvidenceConfigDefaultsAndValidation(t *testing.T) {
	config := &agentConfig{
		ApiConfig: &apiConfig{Url: "http://localhost:8080"},
	}
	if err := config.validate(); err != nil {
		t.Fatalf("expected no-plugin config to be valid: %v", err)
	}
	if !config.agentEvidenceEnabled() {
		t.Fatalf("expected agent evidence to default enabled")
	}
	if !config.agentEvidenceEmitOnRunCompletion() {
		t.Fatalf("expected agent evidence to default to emit on run completion")
	}
	interval, err := config.agentEvidenceInterval()
	if err != nil {
		t.Fatalf("default interval: %v", err)
	}
	if interval != time.Hour {
		t.Fatalf("expected default interval to be 1h, got %s", interval)
	}

	config.AgentEvidence = &agentEvidenceConfig{Interval: "not-a-duration"}
	if err := config.validate(); err == nil {
		t.Fatalf("expected invalid interval to fail validation")
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

func newRuntimeHashTestConfig() *agentConfig {
	schedule := "*/5 * * * *"
	emitOnRunCompletion := true
	enabled := true
	return &agentConfig{
		Daemon:    true,
		Verbosity: 1,
		ApiConfig: &apiConfig{
			Url: "http://example.test",
			Auth: &apiAuthConfig{
				ClientID:     "00000000-0000-0000-0000-000000000001",
				ClientSecret: "client-secret",
			},
		},
		AgentEvidence: &agentEvidenceConfig{
			Enabled:             &enabled,
			EmitOnRunCompletion: &emitOnRunCompletion,
			Interval:            "1h",
		},
		Plugins: map[string]*agentPlugin{
			"plugin-a": {
				ProtocolVersion: DefaultProtocolVersion,
				Schedule:        &schedule,
				Source:          "ghcr.io/example/plugin-a:v1",
				Policies:        []agentPolicy{"policy-a", "policy-b"},
				Config: agentPluginConfig{
					"region": "us-east-1",
					"token":  "secret-token",
				},
				Labels: map[string]string{
					"team": "security",
				},
			},
			"plugin-b": {
				ProtocolVersion: DefaultProtocolVersion,
				Source:          "ghcr.io/example/plugin-b:v1",
			},
		},
	}
}

func newRuntimeHashTestConfigWithReorderedPlugins() *agentConfig {
	config := newRuntimeHashTestConfig()
	plugins := config.Plugins
	config.Plugins = map[string]*agentPlugin{
		"plugin-b": plugins["plugin-b"],
		"plugin-a": plugins["plugin-a"],
	}
	return config
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
