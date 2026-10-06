package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/hashicorp/go-hclog"
)

// writeConfigFile writes content to a temp file with the given extension and returns its path.
func writeConfigFile(t *testing.T, ext, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config."+ext)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func mustLoadBase(t *testing.T, ext, content string) *baseSnapshot {
	t.Helper()
	base, err := loadBase(AgentCmd(), writeConfigFile(t, ext, content))
	if err != nil {
		t.Fatalf("loadBase: %v", err)
	}
	return base
}

const weakTypedConfig = `
api:
  url: http://localhost:8080
plugins:
  aws:
    source: ./plugin-aws
    schedule: "0 * * * *"
    config:
      collect_ip_allow_list: false
      account_id: 123456789012
      port: 22
    policy_data:
      max_auth_tries: 3
      ratio: 0.5
      nested:
        list: [1, 2]
`

// TestLoadBase_WeakDecodingUnchanged checks R51: the file keeps viper's weak decoding exactly
// as today, with no warning and no skip.
func TestLoadBase_WeakDecodingUnchanged(t *testing.T) {
	base := mustLoadBase(t, "yaml", weakTypedConfig)
	if len(base.warnings) != 0 || len(base.skip) != 0 {
		t.Fatalf("expected no warnings or skips, got %v %v", base.warnings, base.skip)
	}
	rt, err := toRuntime(base.declared, base.skip)
	if err != nil {
		t.Fatal(err)
	}
	want := agentPluginConfig{"collect_ip_allow_list": "0", "account_id": "123456789012", "port": "22"}
	if got := rt.Plugins["aws"].Config; !reflect.DeepEqual(got, want) {
		t.Fatalf("plugin config changed: got %#v want %#v", got, want)
	}
}

func TestEnvSourcedPointers(t *testing.T) {
	t.Setenv("CCF_PLUGINS_GITHUB_CONFIG_TOKEN", "from-env")
	base := mustLoadBase(t, "yaml", `
api:
  url: http://localhost:8080
plugins:
  github:
    source: ./plugin-github
    config:
      token: from-file
      org: acme
`)
	if want := []string{"/plugins/github/config/token"}; !reflect.DeepEqual(base.envSourced, want) {
		t.Fatalf("envSourced = %v, want %v", base.envSourced, want)
	}
	if got := base.declared.Plugins["github"].Config["token"]; got != "from-env" {
		t.Fatalf("expected env value to win, got %q", got)
	}
}

func TestLoadBase_BadFileScheduleIsTolerated(t *testing.T) {
	base := mustLoadBase(t, "yaml", `
api:
  url: http://localhost:8080
plugins:
  ssh:
    source: ./plugin-ssh
    schedule: "not a cron"
  github:
    source: ./plugin-github
`)
	if len(base.warnings) != 1 || base.warnings[0].Path != "/plugins/ssh/schedule" || base.warnings[0].Code != agentconfig.FieldCodeCron {
		t.Fatalf("expected one cron warning, got %#v", base.warnings)
	}
	rt, err := toRuntime(base.declared, base.skip)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rt.Plugins["ssh"]; ok {
		t.Fatalf("expected ssh to be skipped")
	}
	if _, ok := rt.Plugins["github"]; !ok {
		t.Fatalf("expected github to run")
	}
	if _, ok := base.declared.Plugins["ssh"]; !ok {
		t.Fatalf("skipped plugin must stay in the declared (reported) config")
	}
}

// TestLoadBase_FileOriginWarnOnly pins R34/R51: values that load on main keep loading. They
// are reported as warnings, the value is unchanged and no plugin is skipped.
func TestLoadBase_FileOriginWarnOnly(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantPath string
		check    func(t *testing.T, rt *agentConfig)
	}{
		{
			name:     "negative verbosity",
			content:  "verbosity: -1\napi:\n  url: http://localhost:8080\nplugins:\n  ssh:\n    source: ./plugin-ssh\n",
			wantPath: "/verbosity",
			check: func(t *testing.T, rt *agentConfig) {
				if rt.Verbosity != -1 || rt.logVerbosity() != int32(hclog.Warn) {
					t.Fatalf("verbosity -1 must stay Warn level, got %d", rt.Verbosity)
				}
			},
		},
		{
			name:     "literal env placeholder in labels",
			content:  "api:\n  url: http://localhost:8080\nplugins:\n  ssh:\n    source: ./plugin-ssh\n    labels:\n      team: \"${env:TEAM}\"\n",
			wantPath: "/plugins/ssh/labels/team",
			check: func(t *testing.T, rt *agentConfig) {
				if got := rt.Plugins["ssh"].Labels["team"]; got != "${env:TEAM}" {
					t.Fatalf("the label must be passed through unchanged, got %q", got)
				}
			},
		},
		{
			name:     "literal env placeholder in policy_data",
			content:  "api:\n  url: http://localhost:8080\nplugins:\n  ssh:\n    source: ./plugin-ssh\n    policy_data:\n      url: \"${env:URL}\"\n",
			wantPath: "/plugins/ssh/policy_data/url",
			check: func(t *testing.T, rt *agentConfig) {
				if got := rt.Plugins["ssh"].PolicyData["url"]; got != "${env:URL}" {
					t.Fatalf("policy_data must be passed through unchanged, got %v", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := mustLoadBase(t, "yaml", tt.content)
			if len(base.warnings) != 1 || base.warnings[0].Path != tt.wantPath {
				t.Fatalf("expected one warning at %s, got %#v", tt.wantPath, base.warnings)
			}
			if len(base.skip) != 0 {
				t.Fatalf("a warn-only problem must not skip a plugin, got %v", base.skip)
			}
			rt, err := toRuntime(base.declared, base.skip)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := rt.Plugins["ssh"]; !ok {
				t.Fatal("the plugin must run")
			}
			tt.check(t, rt)
		})
	}

}

// TestLoadBase_LoadsAsOnMain: YAML that JSON cannot represent loads, and a key the agent does
// not know (here a leftover policy_bundles block) is ignored, as on main.
func TestLoadBase_LoadsAsOnMain(t *testing.T) {
	base := mustLoadBase(t, "yaml", "api:\n  url: http://localhost:8080\nplugins:\n  ssh:\n    source: ./plugin-ssh\n    policy_data:\n      ratio: .nan\n      max: .inf\n")
	if base.declared.Plugins["ssh"] == nil {
		t.Fatalf("plugin ssh missing: %#v", base.declared.Plugins)
	}
	base = mustLoadBase(t, "yaml", "api:\n  url: http://localhost:8080\npolicy_bundles:\n  ssh:\n    modules:\n      a.rego: package a\nplugins:\n  ssh:\n    source: ./plugin-ssh\n")
	if base.declared.Plugins["ssh"] == nil || len(base.warnings) != 0 {
		t.Fatalf("an unknown key must be ignored: %#v %#v", base.declared.Plugins, base.warnings)
	}
}

func TestLoadBase_MissingAPIURLIsFatal(t *testing.T) {
	_, err := loadBase(AgentCmd(), writeConfigFile(t, "yaml", `
api:
  auth:
    client_id: 123e4567-e89b-12d3-a456-426614174000
    client_secret: s
plugins:
  ssh:
    source: ./plugin-ssh
    schedule: "not a cron"
`))
	var verrs agentconfig.ValidationErrors
	if !errors.As(err, &verrs) {
		t.Fatalf("expected validation errors, got %v", err)
	}
	if len(verrs) != 1 || verrs[0].Path != "/api/url" {
		t.Fatalf("expected only the api.url error to be fatal, got %v", verrs)
	}
}

func TestToRuntime_DisabledPluginDropped(t *testing.T) {
	base := mustLoadBase(t, "yaml", `
api:
  url: http://localhost:8080
plugins:
  ssh:
    source: ./plugin-ssh
    enabled: false
  github:
    source: ./plugin-github
`)
	rt, err := toRuntime(base.declared, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rt.Plugins["ssh"]; ok {
		t.Fatalf("disabled plugin must not be in the runtime config")
	}
	if p := base.declared.Plugins["ssh"]; p == nil || p.IsEnabled() {
		t.Fatalf("disabled plugin must stay declared, got %#v", p)
	}
}

func TestToRuntime_ProtocolVersion(t *testing.T) {
	base := mustLoadBase(t, "yaml", `
api:
  url: http://localhost:8080
plugins:
  auto:
    source: ./plugin-a
  pinned:
    source: ./plugin-b
    protocol_version: 2
`)
	rt, err := toRuntime(base.declared, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := rt.Plugins["auto"]; p.protocolSet || p.ProtocolVersion != DefaultProtocolVersion {
		t.Fatalf("auto plugin: %#v", p)
	}
	if p := rt.Plugins["pinned"]; !p.protocolSet || p.ProtocolVersion != RunnerV2ProtocolVersion {
		t.Fatalf("pinned plugin: %#v", p)
	}
}
