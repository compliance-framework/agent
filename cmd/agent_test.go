package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/viper"
)

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
			name: "No API Configuration",
			configYamlContent: `
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
	fetchAnnotations := func(source string, option ...remote.Option) (map[string]string, error) {
		lookupCount++
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
	runner.resolvePluginProtocols()

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
	fetchAnnotations := func(source string, option ...remote.Option) (map[string]string, error) {
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
	runner.resolvePluginProtocols()

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
			name:            "Uses runner-v2 for v2",
			protocolVersion: RunnerV2ProtocolVersion,
			expected:        "runner-v2",
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
