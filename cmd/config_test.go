package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"google.golang.org/protobuf/proto"
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

func TestDecodePolicyBundles_PreservesModuleKeys(t *testing.T) {
	tests := []struct {
		ext     string
		content string
	}{
		{
			ext: "yaml",
			content: `
api:
  url: http://localhost:8080
policy_bundles:
  ssh:
    modules:
      Policies/Max.Auth.rego: |
        package compliance_framework.max_auth
      a.b/c.rego: "package compliance_framework.c"
`,
		},
		{
			ext: "json",
			content: `{
  "api": {"url": "http://localhost:8080"},
  "policy_bundles": {"ssh": {"modules": {
    "Policies/Max.Auth.rego": "package compliance_framework.max_auth\n",
    "a.b/c.rego": "package compliance_framework.c"
  }}}
}`,
		},
		{
			ext: "toml",
			content: `
[api]
url = "http://localhost:8080"

[policy_bundles.ssh.modules]
"Policies/Max.Auth.rego" = """package compliance_framework.max_auth
"""
"a.b/c.rego" = "package compliance_framework.c"
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			base := mustLoadBase(t, tt.ext, tt.content)
			bundle := base.declared.PolicyBundles["ssh"]
			if bundle == nil {
				t.Fatalf("expected ssh bundle, got %#v", base.declared.PolicyBundles)
			}
			if got := bundle.Modules["Policies/Max.Auth.rego"]; got != "package compliance_framework.max_auth\n" {
				t.Fatalf("mixed-case module lost or altered: %q (modules %v)", got, bundle.Modules)
			}
			if got := bundle.Modules["a.b/c.rego"]; got != "package compliance_framework.c" {
				t.Fatalf("dotted module lost or altered: %q (modules %v)", got, bundle.Modules)
			}
		})
	}
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
	rt, err := toRuntime(base.declared, nil, base.skip)
	if err != nil {
		t.Fatal(err)
	}
	want := agentPluginConfig{"collect_ip_allow_list": "0", "account_id": "123456789012", "port": "22"}
	if got := rt.Plugins["aws"].Config; !reflect.DeepEqual(got, want) {
		t.Fatalf("plugin config changed: got %#v want %#v", got, want)
	}
}

// TestWeakDecoding_SurvivesUnrelatedOverlay checks that an overlay touching only the schedule
// leaves the plugin's config and policy_data unchanged on the wire (R51).
func TestWeakDecoding_SurvivesUnrelatedOverlay(t *testing.T) {
	base := mustLoadBase(t, "yaml", weakTypedConfig)
	fileOnly, err := toRuntime(base.declared, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := agentconfig.Merge(base.declared, json.RawMessage(`{"plugins":{"aws":{"schedule":"*/5 * * * *"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	withOverlay, err := toRuntime(merged, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fileOnly.Plugins["aws"].Config, withOverlay.Plugins["aws"].Config) {
		t.Fatalf("config changed by an unrelated overlay: %#v vs %#v", fileOnly.Plugins["aws"].Config, withOverlay.Plugins["aws"].Config)
	}
	a, err := mapToStruct(fileOnly.Plugins["aws"].PolicyData)
	if err != nil {
		t.Fatal(err)
	}
	b, err := mapToStruct(withOverlay.Plugins["aws"].PolicyData)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(a, b) {
		t.Fatalf("policy_data structpb differs: %v vs %v", a, b)
	}
	if got := *withOverlay.Plugins["aws"].Schedule; got != "*/5 * * * *" {
		t.Fatalf("overlay schedule not applied: %q", got)
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
	rt, err := toRuntime(base.declared, nil, base.skip)
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

func TestPartitionByOrigin(t *testing.T) {
	errs := agentconfig.ValidationErrors{
		{Path: "/plugins/ssh/schedule", Code: agentconfig.FieldCodeCron, Message: "bad cron"},
		{Path: "/plugins/github/source", Code: agentconfig.FieldCodeRequired, Message: "source required"},
	}
	t.Run("overlay touches another field of the same plugin", func(t *testing.T) {
		p := partitionByOrigin(errs, []string{"/plugins/ssh/labels/team"})
		if len(p.overlay) != 0 || len(p.warnings) != 1 || len(p.fatal) != 1 {
			t.Fatalf("unexpected partition %#v", p)
		}
		if _, ok := p.skip["ssh"]; !ok {
			t.Fatalf("expected ssh skipped, got %v", p.skip)
		}
	})
	t.Run("overlay sets the schedule", func(t *testing.T) {
		p := partitionByOrigin(errs, []string{"/plugins/ssh/schedule"})
		if len(p.overlay) != 1 || p.overlay[0].Path != "/plugins/ssh/schedule" || len(p.warnings) != 0 {
			t.Fatalf("unexpected partition %#v", p)
		}
	})
	t.Run("overlay adds the plugin", func(t *testing.T) {
		p := partitionByOrigin(errs, []string{"/plugins/ssh"})
		if len(p.overlay) != 1 {
			t.Fatalf("a prefix pointer must make the error overlay-origin, got %#v", p)
		}
	})
	t.Run("segment-wise, not string-wise", func(t *testing.T) {
		p := partitionByOrigin(errs, []string{"/plugins/ss"})
		if len(p.overlay) != 0 {
			t.Fatalf("/plugins/ss must not match /plugins/ssh, got %#v", p)
		}
	})
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
	rt, err := toRuntime(base.declared, nil, nil)
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
	rt, err := toRuntime(base.declared, nil, nil)
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

func TestLoadBase_PolicyBundlesUnsupportedFormat(t *testing.T) {
	_, err := loadBase(AgentCmd(), writeConfigFile(t, "env", "API.URL=http://localhost:8080\nPOLICY_BUNDLES=x\n"))
	if err == nil || !strings.Contains(err.Error(), "policy_bundles is only supported") {
		t.Fatalf("expected unsupported-format error, got %v", err)
	}
}
