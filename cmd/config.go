package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// baseSnapshot is one load of the local configuration: the file merged with CLI flags and
// bound environment variables. It is immutable once built.
//
// declared is the declared form (agentconfig.Config): it is what gets merged, classified,
// validated, redacted, digested and reported. The runtime form (*agentConfig) is built from
// it by toRuntime.
type baseSnapshot struct {
	declared agentconfig.Config // file ⊕ CLI flags ⊕ bound env
	raw      []byte             // exact bytes read (one read per load)
	// warnings are tolerated file-origin problems (R34): reported, never fatal.
	warnings []agentconfig.FieldError
	// skip holds the plugins dropped from the runtime because of a tolerated problem.
	skip map[string]string
}

// toleratedFileRules are the validation rules whose failure is non-fatal when the value comes
// from the local file (R34). Today a bad file schedule only logs "Error adding plugin
// schedule" and the plugin never runs; everything else that fails validation fails startup.
// This list is closed: rules for new features never go here, because no existing file can
// depend on them.
var toleratedFileRules = []*regexp.Regexp{
	regexp.MustCompile(`^/plugins/[^/]+/schedule$`),
}

func isToleratedFileRule(e agentconfig.FieldError) bool {
	for _, re := range toleratedFileRules {
		if re.MatchString(e.Path) {
			return true
		}
	}
	return false
}

// isWarnOnlyFileRule reports whether a file-origin error is a warning that neither skips a
// plugin nor changes the value (R34, R51; owner review of agent#95). These are values that
// load on main with a meaning the agent keeps:
//   - a negative verbosity: hclog.Info - v, i.e. a quieter agent (-1 = Warn);
//   - a literal ${env:...} outside plugins.*.config (labels, policy_data, ...): an opaque
//     string handed to the plugin or to Rego, never resolved.
func isWarnOnlyFileRule(e agentconfig.FieldError) bool {
	return e.Path == "/verbosity" || e.Code == agentconfig.FieldCodeEnvLocation
}

// newAgentViper builds a fresh viper for one load (R32): the watcher goroutine and the loader
// never share an instance.
func newAgentViper(configPath string) (*viper.Viper, error) {
	ext := configExt(configPath)
	v := viper.New()
	v.SetConfigType(ext)
	v.SetEnvPrefix("CCF")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := bindAgentEnv(v); err != nil {
		return nil, err
	}
	return v, nil
}

func configExt(configPath string) string {
	return strings.ToLower(strings.TrimPrefix(filepath.Ext(configPath), "."))
}

func bindAgentEnv(config *viper.Viper) error {
	for key, envVar := range map[string]string{
		"api.auth.client_id":     "CCF_API_AUTH_CLIENT_ID",
		"api.auth.client_secret": "CCF_API_AUTH_CLIENT_SECRET",
	} {
		if err := config.BindEnv(key, envVar); err != nil {
			return err
		}
	}

	return nil
}

// applyFlagOverrides merges CLI flags that were explicitly set into the viper config.
func applyFlagOverrides(cmd *cobra.Command, v *viper.Viper) error {
	// Daemon has a default false value, which will override all values passed through Viper.
	// We need to check whether it was actually passed `Changed()`, and then merge its value into our config.
	if flag := cmd.Flags().Lookup("daemon"); flag != nil && flag.Changed {
		isDaemon, err := cmd.Flags().GetBool("daemon")
		if err != nil {
			return err
		}
		if err := v.MergeConfigMap(map[string]interface{}{"daemon": isDaemon}); err != nil {
			return err
		}
	}

	if flag := cmd.Flags().Lookup("verbose"); flag != nil && flag.Changed {
		verbosity, err := cmd.Flags().GetCount("verbose")
		if err != nil {
			return err
		}
		if err := v.MergeConfigMap(map[string]interface{}{"verbosity": verbosity}); err != nil {
			return err
		}
	}
	return nil
}

// declaredFromViper decodes the declared config from a viper that has read the file. It uses
// viper's default (weakly typed) decoder, exactly as the agent always has (R51): for example
// a YAML `false` plugin config value becomes "0" and a number becomes its decimal string.
func declaredFromViper(cmd *cobra.Command, v *viper.Viper) (agentconfig.Config, error) {
	if err := applyFlagOverrides(cmd, v); err != nil {
		return agentconfig.Config{}, err
	}

	var declared agentconfig.Config
	if err := v.Unmarshal(&declared); err != nil {
		return agentconfig.Config{}, err
	}

	markNullPlugins(v, &declared)
	if err := checkExplicitZeroProtocol(v, declared); err != nil {
		return agentconfig.Config{}, err
	}
	return declared, nil
}

// markNullPlugins keeps `plugins: {x: null}` as a nil entry so validation rejects it, as it
// always has.
func markNullPlugins(v *viper.Viper, declared *agentconfig.Config) {
	for name, rawPlugin := range v.GetStringMap("plugins") {
		if rawPlugin != nil {
			continue
		}
		if declared.Plugins == nil {
			declared.Plugins = map[string]*agentconfig.Plugin{}
		}
		if _, ok := declared.Plugins[name]; !ok {
			declared.Plugins[name] = nil
		}
	}
}

// checkExplicitZeroProtocol rejects an explicit `protocol_version: 0` in the file (R9). In the
// declared form 0 means "auto", so the explicit value is only visible to viper.
func checkExplicitZeroProtocol(v *viper.Viper, declared agentconfig.Config) error {
	names := make([]string, 0)
	for name, rawPlugin := range v.GetStringMap("plugins") {
		pluginMap, ok := rawPlugin.(map[string]interface{})
		if !ok {
			continue
		}
		if _, set := pluginMap["protocol_version"]; !set {
			continue
		}
		if p := declared.Plugins[name]; p != nil && p.ProtocolVersion == 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	return fmt.Errorf("plugin %s has unsupported protocol_version=0; supported values are %d and %d", names[0], DefaultProtocolVersion, RunnerV2ProtocolVersion)
}

// loadBase reads and validates the local configuration. It builds a fresh viper per call
// (R32). A returned error means the file is unusable (fatal at startup; keep last-known-good
// on reload). Tolerated file problems (R34) are returned as warnings and skipped plugins.
func loadBase(cmd *cobra.Command, configPath string) (*baseSnapshot, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	v, err := newAgentViper(configPath)
	if err != nil {
		return nil, err
	}
	if err := v.ReadConfig(bytes.NewReader(raw)); err != nil {
		return nil, err
	}
	return baseFromViper(cmd, v, raw)
}

// baseFromViper finishes loadBase on a viper that has read raw.
func baseFromViper(cmd *cobra.Command, v *viper.Viper, raw []byte) (*baseSnapshot, error) {
	declared, err := declaredFromViper(cmd, v)
	if err != nil {
		return nil, err
	}

	base := &baseSnapshot{
		declared: declared,
		raw:      raw,
	}
	part := partitionByOrigin(declared.Validate())
	if len(part.fatal) > 0 {
		return nil, agentconfig.ValidationErrors(part.fatal)
	}
	base.warnings = part.warnings
	base.skip = part.skip
	return base, nil
}

// validationPartition is the R34 split of a config's validation errors.
type validationPartition struct {
	fatal    []agentconfig.FieldError // file-origin, not tolerated: fatal
	warnings []agentconfig.FieldError // file-origin, tolerated or warn-only: reported
	skip     map[string]string        // plugin name -> reason, for tolerated (skip) errors
}

// partitionByOrigin splits the validation errors of the file (R34): tolerated rules become
// warnings (and the plugin is skipped), warn-only rules become warnings (nothing is skipped or
// changed), the rest is fatal.
func partitionByOrigin(err error) validationPartition {
	var out validationPartition
	if err == nil {
		return out
	}
	var errs agentconfig.ValidationErrors
	if !errors.As(err, &errs) {
		out.fatal = []agentconfig.FieldError{{Path: "", Code: agentconfig.FieldCodeInvalidValue, Message: err.Error()}}
		return out
	}
	for _, e := range errs {
		switch {
		case isToleratedFileRule(e):
			out.warnings = append(out.warnings, e)
			if segs := agentconfig.SplitPointer(e.Path); len(segs) >= 2 && segs[0] == "plugins" {
				if out.skip == nil {
					out.skip = map[string]string{}
				}
				out.skip[segs[1]] = e.Message
			}
		case isWarnOnlyFileRule(e):
			out.warnings = append(out.warnings, e)
		default:
			out.fatal = append(out.fatal, e)
		}
	}
	return out
}

// toRuntime converts a merged, env-resolved declared config into the runtime structs.
// Disabled plugins and plugins named in skip (R34) are dropped: they get no cron, no download
// and no run state, but they stay in the declared form and in reports.
func toRuntime(c agentconfig.Config, skip map[string]string) (*agentConfig, error) {
	out := &agentConfig{
		Daemon:    c.Daemon,
		Verbosity: c.Verbosity,
		Plugins:   map[string]*agentPlugin{},
	}
	if c.API != nil {
		out.ApiConfig = &apiConfig{Url: c.API.URL}
		if c.API.Auth != nil {
			out.ApiConfig.Auth = &apiAuthConfig{
				ClientID:     c.API.Auth.ClientID,
				ClientSecret: c.API.Auth.ClientSecret,
			}
		}
	}
	if c.AgentEvidence != nil {
		out.AgentEvidence = &agentEvidenceConfig{
			Enabled:             cloneBool(c.AgentEvidence.Enabled),
			EmitOnRunCompletion: cloneBool(c.AgentEvidence.EmitOnRunCompletion),
			Interval:            c.AgentEvidence.Interval,
		}
	}
	for name, p := range c.Plugins {
		if p == nil {
			return nil, fmt.Errorf("plugin %s has null configuration", name)
		}
		if !p.IsEnabled() {
			continue
		}
		if _, skipped := skip[name]; skipped {
			continue
		}
		rp := &agentPlugin{
			ProtocolVersion: p.ProtocolVersion,
			protocolSet:     p.ProtocolVersion != 0,
			Source:          p.Source,
			Config:          agentPluginConfig(copyStringMapKeepEmpty(p.Config)),
			Labels:          copyStringMapKeepEmpty(p.Labels),
			PolicyData:      p.PolicyData,
			PolicyBehavior:  p.PolicyBehavior,
		}
		if p.Schedule != nil {
			s := *p.Schedule
			rp.Schedule = &s
		}
		if p.Policies != nil {
			rp.Policies = make([]agentPolicy, 0, len(p.Policies))
			for _, e := range p.Policies {
				rp.Policies = append(rp.Policies, agentPolicy(e))
			}
		}
		out.Plugins[name] = rp
	}
	updateAllPluginProtocols(out)
	return out, nil
}

func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

// copyStringMapKeepEmpty copies m, keeping nil as nil and empty as empty.
func copyStringMapKeepEmpty(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// validateAPIConfig validates a runtime api block with the shared rules (api.url required,
// both or neither credential, client_id a UUID).
func validateAPIConfig(config *apiConfig) error {
	declared := agentconfig.Config{}
	if config != nil {
		declared.API = &agentconfig.APIConfig{URL: config.Url}
		if config.Auth != nil {
			declared.API.Auth = &agentconfig.APIAuth{ClientID: config.Auth.ClientID, ClientSecret: config.Auth.ClientSecret}
		}
	}
	return declared.Validate()
}
