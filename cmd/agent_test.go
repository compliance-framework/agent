package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
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
nats:
  url: nats://localhost:4222

plugins:
  test-plugin:
    source: ghcr.io/some-plugin:v1
`,
			valid: true,
		},
		{
			name: "No NATS Configuration",
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
nats:
  url: nats://localhost:4222
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

func TestUUIDUniqueness(t *testing.T) {
	// This seed data will be defined by the plugin author.
	// Each agent instance should generate a reproducible UUID for a plugin/policy combo, but unique onto itself.
	uuidSeedData := map[string]string{
		// Repeatably identify this plugin / policy combination.
		// Rerunning this plugin / policy on the same agent with the same config should generate the same UUID.
		"plugin-name":    "local-ssh",
		"plugin-version": "v1.3.0",
		"policy-version": "v1.2.3",

		// Uniquely identify this agent.
		// If a set of machines is running the same agent config, each should have a unique UUID.
		"agent-version": "v1.0.0",
		"hostname":      "k8s-worker-3",
	}

	// Build a seed string based on the uniqueness parameters
	seed := ""
	for k, v := range uuidSeedData {
		seed = fmt.Sprintf("%s-%s-%s", seed, k, v)
	}

	// Generate the UUID.
	// It will be consistent for this plugin / policy / agent.
	// It will be unique for each agent instance, so different hosts generate different IDs.
	generatedUuid, err := uuid.NewRandomFromReader(strings.NewReader(seed))
	if err != nil {
		t.Errorf("Failed to create UUID from dataset: %v", err)
	}

	fmt.Println(generatedUuid.String())
}
