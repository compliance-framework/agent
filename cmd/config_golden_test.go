package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// goldenHashFixtures are config files whose agentConfigurationHash was recorded BEFORE the
// declared/runtime config refactor (agent-remote-config G0). The hash feeds the `_agent`
// evidence label fallback and the agent evidence UUID, so it must stay byte-identical.
var goldenHashFixtures = []struct {
	name string
	yaml string
	env  map[string]string
	hash string
}{
	{
		name: "minimal",
		yaml: `
api:
  url: http://localhost:8080
`,
		hash: "4f6b1c9d4fc55c1b99e6b9c60ef0b3783d6ca57fdccc4ca4a768a4256a72e842",
	},
	{
		name: "single plugin defaults",
		yaml: `
api:
  url: http://localhost:8080
plugins:
  ssh:
    source: ghcr.io/compliance-framework/plugin-ssh:v1
`,
		hash: "9513a410fcb588cbf62934306061dbc1c3c2a236b1727dacdfef7f02d110bb2a",
	},
	{
		name: "full plugin",
		yaml: `
daemon: true
verbosity: 1
api:
  url: http://localhost:8080
  auth:
    client_id: 123e4567-e89b-12d3-a456-426614174000
    client_secret: s3cret
agent_evidence:
  enabled: true
  emit_on_run_completion: false
  interval: 90m
plugins:
  ssh:
    source: ghcr.io/compliance-framework/plugin-ssh:v1
    schedule: "*/5 * * * *"
    protocol_version: 2
    policies:
      - ghcr.io/compliance-framework/plugin-ssh-policies:v1
      - ./local-policies
    config:
      host: 127.0.0.1
      port: 22
      collect_ip_allow_list: false
      account_id: 123456789012
    labels:
      team: platform
      env: prod
    policy_data:
      max_auth_tries: 3
      nested:
        allowed: [a, b]
    policy_behavior:
      deny: [warn]
  github:
    source: ghcr.io/compliance-framework/plugin-github:v1
    config:
      token: plain-token
`,
		hash: "b3bf4cf694f2aebeeac36762b1a7f4eb89288a9275b7994e99fb2f85183da1c2",
	},
	{
		name: "env sourced plugin config",
		yaml: `
api:
  url: http://localhost:8080
plugins:
  github:
    source: ghcr.io/compliance-framework/plugin-github:v1
    config:
      token: from-file
`,
		env:  map[string]string{"CCF_PLUGINS_GITHUB_CONFIG_TOKEN": "from-env"},
		hash: "402b411f87e7d4ab32e3148317fc24e01e98347451b1e5af5bceaa5a29cc4175",
	},
	{
		name: "agent evidence disabled",
		yaml: `
api:
  url: http://localhost:8080
agent_evidence:
  enabled: false
plugins:
  a:
    source: ./plugin-a
    protocol_version: 1
  b:
    source: ./plugin-b
    schedule: "@hourly"
`,
		hash: "40d4e852545aad49f8aad499df08051195b10b7c91cb1013c2bc19f6388ead82",
	},
}

// loadGoldenFixture loads a fixture through the agent's file loader. It is the only line that
// changes when the loader is refactored.
func loadGoldenFixture(t *testing.T, yaml string) *agentConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	base, err := loadBase(AgentCmd(), path)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	config, err := toRuntime(base.declared, nil, base.skip)
	if err != nil {
		t.Fatalf("runtime fixture: %v", err)
	}
	return config
}

func TestAgentConfigurationHashGolden(t *testing.T) {
	for _, fx := range goldenHashFixtures {
		t.Run(fx.name, func(t *testing.T) {
			for k, v := range fx.env {
				t.Setenv(k, v)
			}
			config := loadGoldenFixture(t, fx.yaml)
			if got := agentConfigurationHash(config); got != fx.hash {
				t.Fatalf("agentConfigurationHash changed: got %s want %s", got, fx.hash)
			}
		})
	}
}
