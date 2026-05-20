package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/compliance-framework/agent/internal"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/api/sdk"
	sdktypes "github.com/compliance-framework/api/sdk/types"
	"github.com/coreos/go-systemd/v22/daemon"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/fsnotify/fsnotify"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type apiAuthConfig struct {
	ClientID     string `json:"client_id" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret" mapstructure:"client_secret"`
}

type apiConfig struct {
	Url  string         `json:"url" mapstructure:"url"`
	Auth *apiAuthConfig `json:"auth,omitempty" mapstructure:"auth"`
}

type agentPolicy string

type agentPluginConfig map[string]string

type agentPlugin struct {
	ProtocolVersion int32                  `mapstructure:"protocol_version"`
	Schedule        *string                `mapstructure:"schedule,omitempty"`
	Source          string                 `mapstructure:"source"`
	Policies        []agentPolicy          `mapstructure:"policies"`
	PolicyBehavior  map[string][]string    `mapstructure:"policy_behavior,omitempty"`
	Config          agentPluginConfig      `mapstructure:"config"`
	Labels          map[string]string      `mapstructure:"labels"`
	PolicyData      map[string]interface{} `mapstructure:"policy_data,omitempty"`
	protocolSet     bool
}

type agentEvidenceConfig struct {
	Enabled             *bool  `mapstructure:"enabled,omitempty"`
	EmitOnRunCompletion *bool  `mapstructure:"emit_on_run_completion,omitempty"`
	Interval            string `mapstructure:"interval,omitempty"`
}

type agentConfig struct {
	Daemon        bool                    `mapstructure:"daemon"`
	Verbosity     int32                   `mapstructure:"verbosity"`
	ApiConfig     *apiConfig              `mapstructure:"api"`
	Plugins       map[string]*agentPlugin `mapstructure:"plugins"`
	AgentEvidence *agentEvidenceConfig    `mapstructure:"agent_evidence"`
}

// logVerbosity reverses our verbosity "increase" to hclog's reversed "decrease."
// 1 for us means INFO. 1 for hclog means trace.
// 3 for us means TRACE. 3 for hclog means INFO.
// You can see hclog's verbosity here: https://github.com/hashicorp/go-hclog/blob/cb8687c9c619227eac510d0a76d23997fb6667d3/logger.go#L25
func (ac *agentConfig) logVerbosity() int32 {
	return int32(hclog.Info) - ac.Verbosity
}

func (ac *agentConfig) validate() error {
	if err := ac.ApiConfig.validate(); err != nil {
		return err
	}

	if _, err := ac.agentEvidenceInterval(); err != nil {
		return err
	}

	for name, pluginConfig := range ac.Plugins {
		if pluginConfig == nil {
			return fmt.Errorf("plugin %s has null configuration", name)
		}

		if pluginConfig.ProtocolVersion == 0 {
			if pluginConfig.protocolSet {
				return fmt.Errorf("plugin %s has unsupported protocol_version=%d; supported values are %d and %d", name, pluginConfig.ProtocolVersion, DefaultProtocolVersion, RunnerV2ProtocolVersion)
			}

			continue
		}

		if !isSupportedProtocolVersion(pluginConfig.ProtocolVersion) {
			return fmt.Errorf("plugin %s has unsupported protocol_version=%d; supported values are %d and %d", name, pluginConfig.ProtocolVersion, DefaultProtocolVersion, RunnerV2ProtocolVersion)
		}

		// Validate policy_behavior mapping
		if len(pluginConfig.PolicyBehavior) > 0 {
			for policySource, behaviors := range pluginConfig.PolicyBehavior {
				if len(behaviors) == 0 {
					return fmt.Errorf("plugin %s has empty behavior array for policy source %s", name, policySource)
				}
				for _, behavior := range behaviors {
					if strings.TrimSpace(behavior) == "" {
						return fmt.Errorf("plugin %s has empty behavior string in array for policy source %s", name, policySource)
					}
				}
				// Note: We don't validate if policySource matches any policy path here.
				// Non-matching keys will be ignored during mapping with a warning.
			}
		}
	}

	return nil
}

// findMatchingPolicy finds the policy path that contains the given substring
func findMatchingPolicy(substring string, policies []agentPolicy) (agentPolicy, bool) {
	for _, policy := range policies {
		if strings.Contains(string(policy), substring) {
			return policy, true
		}
	}
	return "", false
}

// buildBehaviorMapping converts policy_behavior keys to resolved paths
// Returns the mapping and a list of keys that didn't match any policy
func buildBehaviorMapping(policyBehavior map[string][]string, policyLocations map[string]string, policies []agentPolicy) (map[string][]string, []string) {
	mapping := make(map[string][]string)
	unmatchedKeys := []string{}
	for policySource, behaviors := range policyBehavior {
		if policy, found := findMatchingPolicy(policySource, policies); found {
			if resolvedPath, exists := policyLocations[string(policy)]; exists {
				mapping[resolvedPath] = behaviors
			}
		} else {
			unmatchedKeys = append(unmatchedKeys, policySource)
		}
	}
	return mapping, unmatchedKeys
}

func (ac *agentConfig) agentEvidenceEnabled() bool {
	if ac == nil || ac.AgentEvidence == nil || ac.AgentEvidence.Enabled == nil {
		return true
	}

	return *ac.AgentEvidence.Enabled
}

func (ac *agentConfig) agentEvidenceEmitOnRunCompletion() bool {
	if ac == nil || ac.AgentEvidence == nil || ac.AgentEvidence.EmitOnRunCompletion == nil {
		return true
	}

	return *ac.AgentEvidence.EmitOnRunCompletion
}

func (ac *agentConfig) agentEvidenceInterval() (time.Duration, error) {
	if ac == nil || ac.AgentEvidence == nil || strings.TrimSpace(ac.AgentEvidence.Interval) == "" {
		return time.Hour, nil
	}

	interval, err := time.ParseDuration(strings.TrimSpace(ac.AgentEvidence.Interval))
	if err != nil {
		return 0, fmt.Errorf("agent_evidence.interval must be a valid duration: %w", err)
	}

	if interval < 0 {
		return 0, fmt.Errorf("agent_evidence.interval must not be negative")
	}

	return interval, nil
}

func (ac *apiConfig) validate() error {
	if ac == nil {
		return fmt.Errorf("no api config specified in config")
	}

	if strings.TrimSpace(ac.Url) == "" {
		return fmt.Errorf("api url must be configured")
	}

	if ac.hasPartialAuth() {
		return fmt.Errorf("api auth requires both client_id and client_secret when configured")
	}

	if ac.hasAuth() {
		if _, err := uuid.Parse(strings.TrimSpace(ac.Auth.ClientID)); err != nil {
			return fmt.Errorf("api auth client_id must be a valid UUID")
		}
	}

	return nil
}

func (ac *apiConfig) hasAuth() bool {
	return ac != nil &&
		ac.Auth != nil &&
		strings.TrimSpace(ac.Auth.ClientID) != "" &&
		strings.TrimSpace(ac.Auth.ClientSecret) != ""
}

func (ac *apiConfig) hasPartialAuth() bool {
	if ac == nil || ac.Auth == nil {
		return false
	}

	clientID := strings.TrimSpace(ac.Auth.ClientID)
	clientSecret := strings.TrimSpace(ac.Auth.ClientSecret)
	return (clientID == "") != (clientSecret == "")
}

const AgentPluginDir = ".compliance-framework/plugins"
const AgentPolicyDir = ".compliance-framework/policies"
const DefaultProtocolVersion int32 = 1
const RunnerV2ProtocolVersion int32 = 2
const AnnotationProtocolVersionKey = "org.ccf.plugin.protocol.version"
const daemonCronStopTimeout = 30 * time.Second
const agentEvidenceErrorArtifactMaxBytes = 1024 * 1024

type pluginRunStatus string

const (
	pluginRunStatusPending pluginRunStatus = "pending"
	pluginRunStatusRunning pluginRunStatus = "running"
	pluginRunStatusPassing pluginRunStatus = "passing"
	pluginRunStatusFailed  pluginRunStatus = "failed"
)

type pluginRunRecord struct {
	Status     pluginRunStatus
	Error      string
	StartedAt  time.Time
	FinishedAt time.Time
}

type pluginRunSnapshot struct {
	Passing []string
	Failed  []string
	Pending []string
	Errors  map[string]string
}

func AgentCmd() *cobra.Command {
	var agentCmd = &cobra.Command{
		Use:   "agent",
		Short: "long running agent for continuously checking policies against plugin data",
		Long: `The Continuous Compliance Agent is a long running process that continuously checks policy controls
with plugins to ensure continuous compliance.`,
		RunE: agentRunner,
	}

	agentCmd.Flags().CountP("verbose", "v", "Enable verbose output")
	viper.BindPFlag("verbose", agentCmd.Flags().Lookup("verbose"))

	agentCmd.Flags().BoolP("daemon", "d", false, "Specify to run as a long running daemon")
	viper.BindPFlag("daemon", agentCmd.Flags().Lookup("daemon"))

	agentCmd.Flags().StringP("config", "c", "", "Location of config file")
	agentCmd.MarkFlagRequired("config")

	return agentCmd
}

func mergeConfig(cmd *cobra.Command, fileConfig *viper.Viper) (*agentConfig, error) {
	// For now, we are reading from a file. This will probably be updated to a remote source soon.

	// Daemon has a default false value, which will override all values passed through Viper.
	// We need to check whether it was actually passed `Changed()`, and then merge its value into our config.
	if cmd.Flags().Changed("daemon") {
		isDaemon, err := cmd.Flags().GetBool("daemon")
		if err != nil {
			return nil, err
		}

		err = fileConfig.MergeConfigMap(map[string]interface{}{
			"daemon": isDaemon,
		})
		if err != nil {
			return nil, err
		}
	}

	if cmd.Flags().Changed("verbose") {
		verbosity, err := cmd.Flags().GetCount("verbose")
		if err != nil {
			return nil, err
		}
		err = fileConfig.MergeConfigMap(map[string]interface{}{
			"verbosity": verbosity,
		})
		if err != nil {
			return nil, err
		}
	}

	config := &agentConfig{}
	err := fileConfig.Unmarshal(config)

	if err != nil {
		return nil, err
	}

	markExplicitPluginProtocols(fileConfig, config)
	updateAllPluginProtocols(config)

	return config, nil
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

func markExplicitPluginProtocols(fileConfig *viper.Viper, config *agentConfig) {
	rawPlugins := fileConfig.GetStringMap("plugins")
	for name, rawPlugin := range rawPlugins {
		pluginConfig, ok := config.Plugins[name]
		if rawPlugin == nil {
			if config.Plugins == nil {
				config.Plugins = map[string]*agentPlugin{}
			}
			if !ok {
				config.Plugins[name] = nil
			}
			continue
		}

		if !ok || pluginConfig == nil {
			continue
		}

		pluginMap, ok := rawPlugin.(map[string]interface{})
		if !ok {
			continue
		}

		_, pluginConfig.protocolSet = pluginMap["protocol_version"]
	}
}

func updateAllPluginProtocols(agentConfig *agentConfig) {
	for _, pluginConfig := range agentConfig.Plugins {
		if pluginConfig != nil && !pluginConfig.protocolSet && pluginConfig.ProtocolVersion == 0 {
			pluginConfig.ProtocolVersion = DefaultProtocolVersion
		}
	}
}

func isSupportedProtocolVersion(protocolVersion int32) bool {
	return protocolVersion == DefaultProtocolVersion || protocolVersion == RunnerV2ProtocolVersion
}

func protocolVersionFromAnnotations(annotations map[string]string) (int32, bool) {
	value, ok := annotations[AnnotationProtocolVersionKey]
	if !ok {
		return 0, false
	}

	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, false
	}

	if parsed < 1 {
		return 0, false
	}

	if !isSupportedProtocolVersion(int32(parsed)) {
		return 0, false
	}

	return int32(parsed), true
}

func runnerDispenseName(protocolVersion int32) (string, error) {
	switch protocolVersion {
	case DefaultProtocolVersion:
		return "runner", nil
	case RunnerV2ProtocolVersion:
		return "runner", nil
	default:
		return "", fmt.Errorf("unsupported plugin protocol_version=%d", protocolVersion)
	}
}

func initRunner(name string, protocolVersion int32, runnerInstance runner.RunnerV2, policyPaths []string, resultsHelper runner.ApiHelper) error {
	if protocolVersion <= DefaultProtocolVersion {
		return nil
	}

	_, err := runnerInstance.Init(&proto.InitRequest{
		PolicyPaths: policyPaths,
	}, resultsHelper)
	if err == nil {
		return nil
	}

	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("plugin %s configured as protocol_version=%d but does not implement Init", name, protocolVersion)
	}

	return err
}

func configureRunner(name string, runnerInstance runner.RunnerV2, config agentPluginConfig, policyData map[string]interface{}) error {
	policyDataStruct, err := mapToStruct(policyData)
	if err != nil {
		return fmt.Errorf("invalid policy_data for plugin %s: %w", name, err)
	}

	_, err = runnerInstance.Configure(&proto.ConfigureRequest{
		Config:     config,
		PolicyData: policyDataStruct,
	})
	return err
}

func mapStringSliceToStruct(m map[string][]string) (*structpb.Struct, error) {
	if m == nil {
		return nil, nil
	}
	fields := make(map[string]*structpb.Value)
	for k, v := range m {
		listValues := make([]*structpb.Value, 0, len(v))
		for _, item := range v {
			listValues = append(listValues, &structpb.Value{
				Kind: &structpb.Value_StringValue{StringValue: item},
			})
		}
		fields[k] = &structpb.Value{
			Kind: &structpb.Value_ListValue{
				ListValue: &structpb.ListValue{Values: listValues},
			},
		}
	}
	return &structpb.Struct{Fields: fields}, nil
}

func loadConfig(cmd *cobra.Command, v *viper.Viper) (*agentConfig, error) {
	err := v.ReadInConfig()
	if err != nil {
		return nil, err
	}

	config, err := mergeConfig(cmd, v)
	if err != nil {
		return nil, err
	}

	err = config.validate()
	if err != nil {
		return nil, err
	}
	return config, nil
}

// Main the entrypoint for the `agent` command
//
// It will read the configuration file, and then run the agent. Various command line flags can
// be used to override the config file.
func agentRunner(cmd *cobra.Command, args []string) error {
	configPath := cmd.Flag("config").Value.String()

	if !path.IsAbs(configPath) {
		workDir, err := os.Getwd()
		if err != nil {
			return err
		}
		configPath = path.Join(workDir, configPath)
	}

	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetEnvPrefix("CCF")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := bindAgentEnv(v); err != nil {
		return err
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "agent",
		Output: os.Stdout,
		Level:  hclog.Debug,
	})

	agentRun := NewAgentRunner()

	ctx, configCancel := context.WithCancel(context.Background())
	defer configCancel()

	v.OnConfigChange(func(in fsnotify.Event) {
		// We want to wait for any running agent processes to finish first.
		logger.Debug("config file changed", "path", in.Name)
		configCancel()
	})
	v.WatchConfig()

	// For the daemon, we run the agent continuously.
	// It will exit as soon as the config changes, and then start again with new configs set.
	for {
		ctx, configCancel = context.WithCancel(context.Background())
		config, err := loadConfig(cmd, v)
		if err != nil {
			logger.Error("Error loading new config", "error", err)
			panic(err)
		}
		agentRun.UpdateConfig(config)
		err = agentRun.Run(ctx)

		if err != nil {
			logger.Error("Error running agent", "error", err)
			os.Exit(1)
		}

		if !config.Daemon {
			break
		}
	}

	configCancel()

	return nil
}

type AgentRunner struct {
	logger     hclog.Logger
	stateMu    sync.RWMutex
	config     *agentConfig
	apiClient  *sdk.Client
	httpClient *http.Client

	pluginLocations      map[string]string
	policyLocations      map[string]string
	activePluginClients  map[*plugin.Client]struct{}
	activePluginClientMu sync.Mutex
	pluginClientsClosing bool
	downloadGroup        singleflight.Group
	fetchAnnotations     func(ctx context.Context, source string, option ...remote.Option) (map[string]string, error)
	runPluginFunc        func(ctx context.Context, name string, pluginConfig *agentPlugin) error

	pluginRunMu                   sync.RWMutex
	pluginRuns                    map[string]pluginRunRecord
	firstAgentEvidenceSendStarted bool

	queryBundles []*rego.Rego
}

func NewAgentRunner() *AgentRunner {
	return &AgentRunner{
		pluginLocations:     map[string]string{},
		policyLocations:     map[string]string{},
		activePluginClients: map[*plugin.Client]struct{}{},
		pluginRuns:          map[string]pluginRunRecord{},
		fetchAnnotations:    internal.GetAnnotations,
		httpClient:          http.DefaultClient,
	}
}

func (ar *AgentRunner) UpdateConfig(config *agentConfig) {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "agent-runner",
		Output: os.Stdout,
		Level:  hclog.Level(config.logVerbosity()),
	})
	client := ar.buildAPIClient(config, logger)

	ar.stateMu.Lock()
	ar.config = config
	ar.logger = logger
	ar.apiClient = client
	ar.stateMu.Unlock()
	ar.resetPluginRunState(config)

	ar.logAPIClientConfig("config updated")
}

func (ar *AgentRunner) buildAPIClient(config *agentConfig, logger hclog.Logger) *sdk.Client {
	if config == nil || config.ApiConfig == nil {
		return nil
	}

	clientConfig := &sdk.Config{
		BaseURL: strings.TrimSpace(config.ApiConfig.Url),
	}
	if config.ApiConfig.hasAuth() {
		clientConfig.AgentAuth = &sdk.AgentAuthConfig{
			ClientID:     strings.TrimSpace(config.ApiConfig.Auth.ClientID),
			ClientSecret: strings.TrimSpace(config.ApiConfig.Auth.ClientSecret),
		}
	}

	if logger != nil {
		logger.Debug("Building shared API SDK client",
			"base_url", clientConfig.BaseURL,
			"auth_enabled", config.ApiConfig.hasAuth(),
			"auth_partial", config.ApiConfig.hasPartialAuth(),
			"client_id", apiAuthClientID(config.ApiConfig),
			"client_secret_set", apiAuthClientSecretSet(config.ApiConfig),
		)
	}

	return sdk.NewClient(ar.httpClient, clientConfig)
}

func (ar *AgentRunner) getAPIClient() *sdk.Client {
	ar.stateMu.RLock()
	client := ar.apiClient
	logger := ar.logger
	ar.stateMu.RUnlock()

	if client != nil {
		return client
	}

	if logger != nil {
		logger.Debug("Shared API SDK client missing; rebuilding from current config")
	}

	ar.stateMu.Lock()
	defer ar.stateMu.Unlock()

	if ar.apiClient == nil {
		ar.apiClient = ar.buildAPIClient(ar.config, ar.logger)
	}
	return ar.apiClient
}

func (ar *AgentRunner) getConfig() *agentConfig {
	ar.stateMu.RLock()
	defer ar.stateMu.RUnlock()

	return ar.config
}

func (ar *AgentRunner) getLogger() hclog.Logger {
	ar.stateMu.RLock()
	defer ar.stateMu.RUnlock()

	return ar.logger
}

func (ar *AgentRunner) resetPluginRunState(config *agentConfig) {
	runs := map[string]pluginRunRecord{}
	if config != nil {
		for name := range config.Plugins {
			runs[name] = pluginRunRecord{Status: pluginRunStatusPending}
		}
	}

	ar.pluginRunMu.Lock()
	ar.pluginRuns = runs
	ar.firstAgentEvidenceSendStarted = false
	ar.pluginRunMu.Unlock()
}

func (ar *AgentRunner) markPluginRunStarted(name string) {
	now := time.Now().UTC()

	ar.pluginRunMu.Lock()
	defer ar.pluginRunMu.Unlock()

	record := ar.pluginRuns[name]
	record.Status = pluginRunStatusRunning
	record.StartedAt = now
	record.FinishedAt = time.Time{}
	ar.pluginRuns[name] = record
}

func (ar *AgentRunner) markPluginRunFinished(name string, err error) {
	now := time.Now().UTC()

	ar.pluginRunMu.Lock()
	defer ar.pluginRunMu.Unlock()

	record := ar.pluginRuns[name]
	if record.StartedAt.IsZero() {
		record.StartedAt = now
	}
	record.FinishedAt = now
	if err != nil {
		record.Status = pluginRunStatusFailed
		record.Error = pluginRunErrorMessage(err)
	} else {
		record.Status = pluginRunStatusPassing
		record.Error = ""
	}
	ar.pluginRuns[name] = record
}

func (ar *AgentRunner) markPluginsWithSourceFailed(source string, err error) {
	config := ar.getConfig()
	if config == nil || err == nil {
		return
	}

	for name, pluginConfig := range config.Plugins {
		if pluginConfig != nil && pluginConfig.Source == source {
			ar.markPluginRunFinished(name, err)
		}
	}
}

func (ar *AgentRunner) markPluginsWithPolicyFailed(policy agentPolicy, err error) {
	config := ar.getConfig()
	if config == nil || err == nil {
		return
	}

	for name, pluginConfig := range config.Plugins {
		if pluginConfig == nil {
			continue
		}
		for _, pluginPolicy := range pluginConfig.Policies {
			if pluginPolicy == policy {
				ar.markPluginRunFinished(name, err)
				break
			}
		}
	}
}

func (ar *AgentRunner) pluginRunSnapshot() pluginRunSnapshot {
	ar.pluginRunMu.RLock()
	defer ar.pluginRunMu.RUnlock()

	snapshot := pluginRunSnapshot{
		Errors: map[string]string{},
	}
	for name, record := range ar.pluginRuns {
		if record.Error != "" {
			snapshot.Failed = append(snapshot.Failed, name)
			snapshot.Errors[name] = record.Error
		} else if record.Status == pluginRunStatusFailed {
			snapshot.Failed = append(snapshot.Failed, name)
			snapshot.Errors[name] = pluginRunErrorMessage(nil)
		}

		switch record.Status {
		case pluginRunStatusPassing:
			snapshot.Passing = append(snapshot.Passing, name)
		case pluginRunStatusFailed:
		case pluginRunStatusRunning:
		default:
			snapshot.Pending = append(snapshot.Pending, name)
		}
	}

	sort.Strings(snapshot.Passing)
	sort.Strings(snapshot.Failed)
	sort.Strings(snapshot.Pending)
	return snapshot
}

func pluginRunErrorMessage(err error) string {
	if err != nil {
		message := strings.TrimSpace(err.Error())
		if message != "" {
			return message
		}
	}

	return "plugin run failed without an error message"
}

func (ar *AgentRunner) reserveFirstAgentEvidenceSend() bool {
	config := ar.getConfig()
	if config == nil || !config.agentEvidenceEnabled() || !config.agentEvidenceEmitOnRunCompletion() {
		return false
	}

	ar.pluginRunMu.Lock()
	defer ar.pluginRunMu.Unlock()

	if ar.firstAgentEvidenceSendStarted {
		return false
	}

	if len(ar.pluginRuns) == 0 {
		return false
	}

	for _, record := range ar.pluginRuns {
		if record.Status == pluginRunStatusPending || record.Status == pluginRunStatusRunning {
			return false
		}
	}

	ar.firstAgentEvidenceSendStarted = true
	return true
}

func (ar *AgentRunner) releaseFirstAgentEvidenceSend() {
	ar.pluginRunMu.Lock()
	ar.firstAgentEvidenceSendStarted = false
	ar.pluginRunMu.Unlock()
}

func (ar *AgentRunner) logAPIClientConfig(event string) {
	ar.stateMu.RLock()
	logger := ar.logger
	config := ar.config
	ar.stateMu.RUnlock()

	if logger == nil {
		return
	}

	logger.Debug("Agent API client configuration",
		"event", event,
		"base_url", apiBaseURL(config),
		"auth_enabled", hasAPIAuth(config),
		"auth_partial", hasPartialAPIAuth(config),
		"client_id", apiClientID(config),
		"client_secret_set", apiClientSecretSet(config),
	)
}

func apiBaseURL(config *agentConfig) string {
	if config == nil || config.ApiConfig == nil {
		return ""
	}

	return strings.TrimSpace(config.ApiConfig.Url)
}

func hasAPIAuth(config *agentConfig) bool {
	return config != nil && config.ApiConfig != nil && config.ApiConfig.hasAuth()
}

func hasPartialAPIAuth(config *agentConfig) bool {
	return config != nil && config.ApiConfig != nil && config.ApiConfig.hasPartialAuth()
}

func apiClientID(config *agentConfig) string {
	if config == nil || config.ApiConfig == nil {
		return ""
	}

	return apiAuthClientID(config.ApiConfig)
}

func apiClientSecretSet(config *agentConfig) bool {
	if config == nil || config.ApiConfig == nil {
		return false
	}

	return apiAuthClientSecretSet(config.ApiConfig)
}

func apiAuthClientID(config *apiConfig) string {
	if config == nil || config.Auth == nil {
		return ""
	}

	return maskClientID(config.Auth.ClientID)
}

func apiAuthClientSecretSet(config *apiConfig) bool {
	if config == nil || config.Auth == nil {
		return false
	}

	return strings.TrimSpace(config.Auth.ClientSecret) != ""
}

func agentIdentityLabel(config *agentConfig) string {
	if config != nil && config.ApiConfig != nil && config.ApiConfig.Auth != nil {
		if clientID := strings.TrimSpace(config.ApiConfig.Auth.ClientID); clientID != "" {
			return clientID
		}
	}

	for _, envName := range []string{"KUBERNETES_POD_NAME", "KUBERNETES_POD"} {
		if podName := strings.TrimSpace(os.Getenv(envName)); podName != "" {
			return podName
		}
	}

	return agentConfigurationHash(config)
}

func agentFoundationalLabels(config *agentConfig) map[string]string {
	return map[string]string{
		"_agent": agentIdentityLabel(config),
		"tool":   "ccf",
		"type":   "operations",
	}
}

type normalizedAgentConfigForHash struct {
	AgentEvidence normalizedAgentEvidenceConfigForHash `json:"agent_evidence"`
	Plugins       []normalizedAgentPluginForHash       `json:"plugins"`
}

type normalizedAgentEvidenceConfigForHash struct {
	Enabled             bool   `json:"enabled"`
	EmitOnRunCompletion bool   `json:"emit_on_run_completion"`
	Interval            string `json:"interval"`
}

type normalizedAgentPluginForHash struct {
	Name            string            `json:"name"`
	ProtocolVersion int32             `json:"protocol_version"`
	Schedule        string            `json:"schedule"`
	Source          string            `json:"source"`
	Policies        []string          `json:"policies"`
	Config          map[string]string `json:"config,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
}

func agentConfigurationHash(config *agentConfig) string {
	normalized := normalizedAgentConfigForHash{
		AgentEvidence: normalizedAgentEvidenceConfigForHash{
			Enabled:             true,
			EmitOnRunCompletion: true,
			Interval:            normalizedAgentEvidenceInterval(config),
		},
	}

	if config != nil {
		normalized.AgentEvidence.Enabled = config.agentEvidenceEnabled()
		normalized.AgentEvidence.EmitOnRunCompletion = config.agentEvidenceEmitOnRunCompletion()

		pluginNames := make([]string, 0, len(config.Plugins))
		for pluginName := range config.Plugins {
			pluginNames = append(pluginNames, pluginName)
		}
		sort.Strings(pluginNames)

		normalized.Plugins = make([]normalizedAgentPluginForHash, 0, len(pluginNames))
		for _, pluginName := range pluginNames {
			pluginConfig := config.Plugins[pluginName]
			normalizedPlugin := normalizedAgentPluginForHash{
				Name:     pluginName,
				Schedule: "* * * * *",
			}
			if pluginConfig != nil {
				normalizedPlugin.ProtocolVersion = effectivePluginProtocolVersion(pluginConfig)
				normalizedPlugin.Source = pluginConfig.Source
				if pluginConfig.Schedule != nil {
					normalizedPlugin.Schedule = *pluginConfig.Schedule
				}
				normalizedPlugin.Policies = make([]string, 0, len(pluginConfig.Policies))
				for _, policy := range pluginConfig.Policies {
					normalizedPlugin.Policies = append(normalizedPlugin.Policies, string(policy))
				}
				normalizedPlugin.Config = copyStringMap(pluginConfig.Config)
				normalizedPlugin.Labels = copyStringMap(pluginConfig.Labels)
			}
			normalized.Plugins = append(normalized.Plugins, normalizedPlugin)
		}
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		sum := sha256.Sum256([]byte(err.Error()))
		return fmt.Sprintf("%x", sum[:])
	}
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func normalizedAgentEvidenceInterval(config *agentConfig) string {
	if config == nil {
		return time.Hour.String()
	}

	interval, err := config.agentEvidenceInterval()
	if err != nil {
		if config.AgentEvidence == nil {
			return ""
		}
		return strings.TrimSpace(config.AgentEvidence.Interval)
	}
	return interval.String()
}

func copyStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}

	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func mapToStruct(m map[string]interface{}) (*structpb.Struct, error) {
	if m == nil {
		return nil, nil
	}
	return structpb.NewStruct(m)
}

func pluginEvidenceLabels(config *agentConfig, pluginName string, pluginConfig *agentPlugin) map[string]string {
	return pluginEvidenceLabelsWithHash(config, pluginName, pluginConfig, agentConfigurationHash(config))
}

func pluginEvidenceLabelsWithHash(config *agentConfig, pluginName string, pluginConfig *agentPlugin, configHash string) map[string]string {
	labels := map[string]string{
		"_agent":  agentIdentityLabel(config),
		"_plugin": pluginName,
	}
	if pluginConfig != nil {
		for k, v := range pluginConfig.Labels {
			labels[k] = v
		}
	}
	return labels
}

func effectivePluginProtocolVersion(pluginConfig *agentPlugin) int32 {
	if pluginConfig == nil {
		return 0
	}
	if pluginConfig.ProtocolVersion == 0 && !pluginConfig.protocolSet {
		return DefaultProtocolVersion
	}
	return pluginConfig.ProtocolVersion
}

func maskClientID(clientID string) string {
	trimmed := strings.TrimSpace(clientID)
	if trimmed == "" {
		return ""
	}

	firstBlock, _, found := strings.Cut(trimmed, "-")
	if !found {
		return firstBlock
	}

	return firstBlock + "-..."
}

func (ar *AgentRunner) Run(ctx context.Context) error {
	config := ar.getConfig()
	logger := ar.getLogger()
	logger.Info("Starting agent", "daemon", config.Daemon)
	ar.allowPluginClientTracking()

	logger.Debug("Pessimistically downloading plugins and policies to fail early in case daemon runs later.")
	err := ar.DownloadPlugins(ctx)
	if err != nil {
		logger.Error("Error downloading plugins", "error", err)
		if evidenceErr := ar.sendAgentRunEvidenceOnStartupFailure(ctx); evidenceErr != nil {
			logger.Error("Error sending agent run evidence", "error", evidenceErr)
		}
		return err
	}

	ar.resolvePluginProtocols(ctx)

	err = ar.DownloadPolicies(ctx)
	if err != nil {
		logger.Error("Error downloading policies", "error", err)
		if evidenceErr := ar.sendAgentRunEvidenceOnStartupFailure(ctx); evidenceErr != nil {
			logger.Error("Error sending agent run evidence", "error", evidenceErr)
		}
		return err
	}
	logger.Debug("Pessimistically downloading plugins and policies worked successfully. Starting the agent.")

	if config.Daemon == true {
		ar.runDaemon(ctx)
		return nil
	}

	return ar.runAllPlugins(ctx)
}

func (ar *AgentRunner) resolvePluginProtocols(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	config := ar.getConfig()
	logger := ar.getLogger()
	for pluginName, pluginConfig := range config.Plugins {
		if pluginConfig == nil || pluginConfig.protocolSet || !internal.IsOCI(pluginConfig.Source) {
			continue
		}

		func() {
			annotationCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			annotations, err := ar.fetchAnnotations(annotationCtx, pluginConfig.Source)
			if err != nil {
				logger.Warn("Failed to fetch plugin annotations, using configured/default protocol version", "plugin", pluginName, "source", pluginConfig.Source, "protocol_version", pluginConfig.ProtocolVersion, "error", err)
				return
			}

			value, ok := annotations[AnnotationProtocolVersionKey]
			if !ok {
				return
			}

			protocolVersion, ok := protocolVersionFromAnnotations(annotations)
			if !ok {
				logger.Warn("Ignoring unsupported plugin protocol version annotation", "plugin", pluginName, "source", pluginConfig.Source, "value", value, "protocol_version", pluginConfig.ProtocolVersion)
				return
			}

			pluginConfig.ProtocolVersion = protocolVersion
		}()
	}
}

// Should never return, either handles any error or panics.
func (ar *AgentRunner) runDaemon(ctx context.Context) {
	logger := ar.getLogger()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)

	agentCron, err := ar.setupCron(ctx)
	if err != nil {
		logger.Error("Error setting up agent cron", "error", err)
		os.Exit(1)
	}

	heartbeatCron, err := ar.setupHeartbeatCron(ctx)
	if err != nil {
		logger.Error("Error setting up heartbeat", "error", err)
		os.Exit(1)
	}
	agentEvidenceCron, err := ar.setupAgentEvidenceCron(ctx)
	if err != nil {
		logger.Error("Error setting up agent evidence", "error", err)
		os.Exit(1)
	}

	// Start the cron and notify readiness
	agentCron.Start()
	heartbeatCron.Start()
	agentEvidenceCron.Start()
	if ar.reserveFirstAgentEvidenceSend() {
		if err := ar.SendAgentRunEvidence(ctx); err != nil {
			ar.releaseFirstAgentEvidenceSend()
			logger.Error("Failed to send agent run evidence", "error", err)
		}
	}
	go daemon.SdNotify(false, "READY=1")

	select {
	case sig := <-sigs:
		logger.Info("received signal to terminate plugins and exit", "signal", sig)
		logger.Debug("Stopping crons")
		agentCronStopCtx := agentCron.Stop()
		heartbeatCronStopCtx := heartbeatCron.Stop()
		agentEvidenceCronStopCtx := agentEvidenceCron.Stop()
		if !waitForCronStop(daemonCronStopTimeout, agentCronStopCtx, heartbeatCronStopCtx, agentEvidenceCronStopCtx) {
			logger.Warn("Timed out waiting for cron jobs to stop before plugin cleanup", "timeout", daemonCronStopTimeout)
		}
		logger.Debug("Shutting down plugins")
		ar.closePluginClients()
		logger.Debug("Exiting")
		os.Exit(0)
	case <-ctx.Done():
		logger.Debug("received cancel signal to return from daemon")
		logger.Debug("Stopping crons")
		agentCronStopCtx := agentCron.Stop()
		heartbeatCronStopCtx := heartbeatCron.Stop()
		agentEvidenceCronStopCtx := agentEvidenceCron.Stop()
		if !waitForCronStop(daemonCronStopTimeout, agentCronStopCtx, heartbeatCronStopCtx, agentEvidenceCronStopCtx) {
			logger.Warn("Timed out waiting for cron jobs to stop before plugin cleanup", "timeout", daemonCronStopTimeout)
		}
		logger.Debug("Shutting down plugins")
		ar.closePluginClients()
		return
	}
}

func waitForCronStop(timeout time.Duration, stopContexts ...context.Context) bool {
	allDone := make(chan struct{})
	waitCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(stopContexts))

	for _, stopCtx := range stopContexts {
		go func(stopCtx context.Context) {
			defer wg.Done()
			select {
			case <-stopCtx.Done():
			case <-waitCtx.Done():
			}
		}(stopCtx)
	}

	go func() {
		wg.Wait()
		close(allDone)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-allDone:
		return true
	case <-timer.C:
		select {
		case <-allDone:
			return true
		default:
			return false
		}
	}
}

type cronLogger struct {
	logger hclog.Logger
}

func (l cronLogger) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, keysAndValues...)
}

func (l cronLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	l.logger.Error(msg, append([]interface{}{"error", err}, keysAndValues...)...)
}

func (ar *AgentRunner) download(ctx context.Context, source string, outputDir string, binaryPath string, optionKey string, logger hclog.Logger, option ...remote.Option) (string, error) {
	lockKey := strings.Join([]string{outputDir, binaryPath, source, optionKey}, "\x00")
	result, err, _ := ar.downloadGroup.Do(lockKey, func() (interface{}, error) {
		return internal.Download(ctx, source, outputDir, binaryPath, logger, option...)
	})
	if err != nil {
		return "", err
	}

	return result.(string), nil
}

func (ar *AgentRunner) setupHeartbeatCron(ctx context.Context) (*cron.Cron, error) {
	logger := ar.getLogger()

	// staggeredSeconds is used to offset the heartbeat by x seconds to prevent a massive influx of heartbeats on
	// the beginning of each minute to the API.
	// The offset will stagger the heartbeats across each minute
	staggeredSeconds := rand.Intn(59)

	c := cron.New(cron.WithParser(cron.NewParser(
		cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
	)))
	staticAgentUUID := uuid.New()
	_, err := c.AddFunc(fmt.Sprintf("%d * * * * *", staggeredSeconds), func() {
		err := ar.SendHeartbeat(ctx, staticAgentUUID)
		if err != nil {
			logger.Error("Failed to send heartbeat", "error", err, "uuid", staticAgentUUID.String())
		}
	})
	if err != nil {
		logger.Error("Error adding heartbeat schedule", "error", err, "uuid", staticAgentUUID.String())
	}
	return c, nil
}

func (ar *AgentRunner) setupAgentEvidenceCron(ctx context.Context) (*cron.Cron, error) {
	logger := ar.getLogger()
	config := ar.getConfig()
	c := cron.New(cron.WithParser(cron.NewParser(
		cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
	)))
	if config == nil || !config.agentEvidenceEnabled() {
		return c, nil
	}

	interval, err := config.agentEvidenceInterval()
	if err != nil {
		return nil, err
	}
	if interval <= 0 {
		return c, nil
	}

	jobLogger := logger.With("job", "agent_evidence", "schedule", "@every "+interval.String())
	job := cron.NewChain(cron.SkipIfStillRunning(cronLogger{logger: jobLogger})).Then(cron.FuncJob(func() {
		if err := ar.SendAgentRunEvidence(ctx); err != nil {
			jobLogger.Error("Failed to send agent run evidence", "error", err)
		}
	}))
	_, err = c.AddJob("@every "+interval.String(), job)
	if err != nil {
		logger.Error("Error adding agent evidence schedule", "error", err)
	}
	return c, nil
}

func (ar *AgentRunner) setupCron(ctx context.Context) (*cron.Cron, error) {
	logger := ar.getLogger()
	parserOptions := cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor
	c := cron.New(cron.WithParser(cron.NewParser(
		parserOptions,
	)))
	config := ar.getConfig()
	runPlugin := ar.runPlugin
	if ar.runPluginFunc != nil {
		runPlugin = ar.runPluginFunc
	}

	for pluginName, pluginConfig := range config.Plugins {
		currentPluginName := pluginName
		currentPluginConfig := pluginConfig
		var schedule string
		if currentPluginConfig.Schedule == nil {
			schedule = "* * * * *"
		} else {
			schedule = *currentPluginConfig.Schedule
		}

		jobLogger := logger.With("plugin", currentPluginName, "schedule", schedule)
		job := cron.NewChain(cron.SkipIfStillRunning(cronLogger{logger: jobLogger})).Then(cron.FuncJob(func() {
			ar.markPluginRunStarted(currentPluginName)
			err := runPlugin(ctx, currentPluginName, currentPluginConfig)
			ar.markPluginRunFinished(currentPluginName, err)
			if err != nil {
				// TODO how will we handle these errors ?
				jobLogger.Error("Error running plugin", "error", err, "protocol_version", currentPluginConfig.ProtocolVersion)
			}
			if ar.reserveFirstAgentEvidenceSend() {
				if evidenceErr := ar.SendAgentRunEvidence(ctx); evidenceErr != nil {
					ar.releaseFirstAgentEvidenceSend()
					jobLogger.Error("Failed to send agent run evidence", "error", evidenceErr)
				}
			}
		}))
		_, err := c.AddJob(schedule, job)

		if err != nil {
			logger.Error("Error adding plugin schedule", "schedule", schedule, "error", err)
			// TODO We should figure out how to handle this, especially in the context of automatically configured
			// agents. We should probably send a health status to the API with errors.
		}
	}
	return c, nil
}

// Run the agent as an instance, this is a single run of the agent that will check the
// policies against the plugins.
//
// Returns:
// - error: any error that occurred during the run
func (ar *AgentRunner) runAllPlugins(ctx context.Context) error {
	config := ar.getConfig()
	client := ar.getAPIClient()
	logger := ar.getLogger()
	logger.Debug("Running all plugins with shared API SDK client",
		"auth_enabled", hasAPIAuth(config),
		"client_id", apiClientID(config),
	)

	defer ar.closePluginClients()

	pluginNames := make([]string, 0, len(config.Plugins))
	for pluginName := range config.Plugins {
		pluginNames = append(pluginNames, pluginName)
	}
	sort.Strings(pluginNames)
	configHash := agentConfigurationHash(config)

	for _, pluginName := range pluginNames {
		pluginConfig := config.Plugins[pluginName]
		ar.markPluginRunStarted(pluginName)
		logger := hclog.New(&hclog.LoggerOptions{
			Name:   fmt.Sprintf("runner.%s", pluginName),
			Output: os.Stdout,
			Level:  hclog.Level(config.logVerbosity()),
		})

		labels := pluginEvidenceLabelsWithHash(config, pluginName, pluginConfig, configHash)

		source := ar.pluginLocations[pluginConfig.Source]

		logger.Debug("Running plugin", "source", source, "protocol_version", pluginConfig.ProtocolVersion)

		if _, err := os.ReadFile(source); err != nil {
			ar.markPluginRunFinished(pluginName, err)
			if evidenceErr := ar.sendAgentRunEvidenceAfterCompleteRun(ctx); evidenceErr != nil {
				logger.Error("Error sending agent run evidence", "error", evidenceErr)
			}
			return err
		}

		runnerInstance, cleanupRunner, err := ar.getRunnerInstance(logger, source, pluginConfig.ProtocolVersion)

		if err != nil {
			ar.markPluginRunFinished(pluginName, err)
			if evidenceErr := ar.sendAgentRunEvidenceAfterCompleteRun(ctx); evidenceErr != nil {
				logger.Error("Error sending agent run evidence", "error", evidenceErr)
			}
			return err
		}
		if err := func() error {
			defer cleanupRunner()

			if err := configureRunner(pluginName, runnerInstance, pluginConfig.Config, pluginConfig.PolicyData); err != nil {
				// What do we do here ?
				//endTimer := time.Now()
				//_, err = client.Results.Create(&sdk.Result{
				//	StreamID:    streamId,
				//	Labels:      resultLabels,
				//	Title:       "Agent has failed to configure plugin.",
				//	Remarks:     "Agent has failed to configure plugin. Fix agent to continue receiving results",
				//	Description: fmt.Errorf("agent execution failed with error. %v", err).Error(),
				//	Start:       startTimer,
				//	End:         &endTimer,
				//})
				return err
			}

			policyPaths := make([]string, 0, len(pluginConfig.Policies))

			for _, inputBundle := range pluginConfig.Policies {
				policyPaths = append(policyPaths, ar.policyLocations[string(inputBundle)])
			}

			// Create a new results helper for the plugin to send results back to
			logger.Debug("Creating plugin API helper",
				"plugin", pluginName,
				"auth_enabled", hasAPIAuth(config),
				"client_id", apiClientID(config),
			)
			resultsHelper := runner.NewApiHelper(logger, client, labels, pluginName)

			if err := initRunner(pluginName, pluginConfig.ProtocolVersion, runnerInstance, policyPaths, resultsHelper); err != nil {
				return err
			}

			// TODO: Send failed results to the database?
			// Convert policy_behavior_mapping to proto format for Eval
			// Build mapping from resolved paths to behaviors using helper function
			behaviorMappingWithResolved, unmatchedKeys := buildBehaviorMapping(pluginConfig.PolicyBehavior, ar.policyLocations, pluginConfig.Policies)
			// Log warnings for unmatched keys
			for _, key := range unmatchedKeys {
				logger.Warn("plugin %s policy_behavior key %s does not match any policy path, ignoring\n", pluginName, key)
			}
			// If all keys were unmatched, log a warning and pass empty mapping to prevent false negatives
			if len(behaviorMappingWithResolved) == 0 && len(pluginConfig.PolicyBehavior) > 0 {
				logger.Warn("plugin %s policy_behavior provided but no keys matched any policy path. Passing empty mapping to prevent false negatives.\n", pluginName)
			}
			// Convert to Struct format
			policyBehaviorStruct, err := mapStringSliceToStruct(behaviorMappingWithResolved)
			if err != nil {
				logger.Error("invalid policy_behavior_mapping for plugin", "plugin", pluginName, "error", err)
				return err
			}
			_, err = runnerInstance.Eval(&proto.EvalRequest{
				PolicyPaths:           policyPaths,
				PolicyBehaviorMapping: policyBehaviorStruct,
			}, resultsHelper)

			if err != nil {
				// What do we do here ?
				//endTimer := time.Now()
				//_, err = client.Results.Create(&sdk.Result{
				//	StreamID:    streamId,
				//	Labels:      resultLabels,
				//	Title:       "Agent has failed to execute policies.",
				//	Remarks:     "Agent has failed to execute policies. Fix agent to continue receiving results",
				//	Description: fmt.Errorf("agent execution failed with error. %v", err).Error(),
				//	Start:       startTimer,
				//	End:         &endTimer,
				//})
				return err
			}

			return nil
		}(); err != nil {
			ar.markPluginRunFinished(pluginName, err)
			if evidenceErr := ar.sendAgentRunEvidenceAfterCompleteRun(ctx); evidenceErr != nil {
				logger.Error("Error sending agent run evidence", "error", evidenceErr)
			}
			return err
		}
		ar.markPluginRunFinished(pluginName, nil)
	}

	if evidenceErr := ar.sendAgentRunEvidenceAfterCompleteRun(ctx); evidenceErr != nil {
		logger.Error("Error sending agent run evidence", "error", evidenceErr)
	}
	return nil
}

func (ar *AgentRunner) sendAgentRunEvidenceAfterCompleteRun(ctx context.Context) error {
	config := ar.getConfig()
	if config == nil || !config.agentEvidenceEnabled() || !config.agentEvidenceEmitOnRunCompletion() {
		return nil
	}

	return ar.SendAgentRunEvidence(ctx)
}

func (ar *AgentRunner) sendAgentRunEvidenceOnStartupFailure(ctx context.Context) error {
	config := ar.getConfig()
	if config == nil || !config.agentEvidenceEnabled() || !config.agentEvidenceEmitOnRunCompletion() {
		return nil
	}

	return ar.SendAgentRunEvidence(ctx)
}

// Run the agent as an instance, this is a single run of the agent that will check the
// policies against the plugins.
//
// Returns:
// - error: any error that occurred during the run
func (ar *AgentRunner) runPlugin(ctx context.Context, name string, plugin *agentPlugin) error {
	config := ar.getConfig()
	client := ar.getAPIClient()
	logger := ar.getLogger()
	logger.Debug("Running single plugin with shared API SDK client",
		"plugin", name,
		"auth_enabled", hasAPIAuth(config),
		"client_id", apiClientID(config),
	)

	policyPaths := make([]string, 0)
	for _, inputBundle := range plugin.Policies {
		policyLocation, err := ar.download(ctx, string(inputBundle), AgentPolicyDir, "policies", "", logger)
		if err != nil {
			return err
		}
		policyPaths = append(policyPaths, policyLocation)
	}

	platform := v1.Platform{
		Architecture: runtime.GOARCH,
		OS:           runtime.GOOS,
	}
	pluginExecutable, err := ar.download(ctx, plugin.Source, AgentPluginDir, "plugin", platformDownloadKey(platform), logger, remote.WithPlatform(platform))

	if err != nil {
		return err
	}

	logger.Info("Running plugin", "source", plugin.Source, "protocol_version", plugin.ProtocolVersion)
	logger.Info("Running plugin", "source", pluginExecutable, "protocol_version", plugin.ProtocolVersion)

	pluginLogger := hclog.New(&hclog.LoggerOptions{
		Name:   fmt.Sprintf("runner.%s", name),
		Output: os.Stdout,
		Level:  hclog.Level(config.logVerbosity()),
	})

	labels := pluginEvidenceLabelsWithHash(config, name, plugin, agentConfigurationHash(config))

	pluginLogger.Debug("Running plugin", "source", pluginExecutable, "protocol_version", plugin.ProtocolVersion)

	if _, err := os.ReadFile(pluginExecutable); err != nil {
		return err
	}

	runnerInstance, cleanupRunner, err := ar.getRunnerInstance(pluginLogger, pluginExecutable, plugin.ProtocolVersion)

	if err != nil {
		return err
	}
	defer cleanupRunner()

	if err := configureRunner(name, runnerInstance, plugin.Config, plugin.PolicyData); err != nil {
		return err
	}

	// Create a new results helper for the plugin to send results back to
	pluginLogger.Debug("Creating plugin API helper",
		"plugin", name,
		"auth_enabled", hasAPIAuth(config),
		"client_id", apiClientID(config),
	)
	resultsHelper := runner.NewApiHelper(pluginLogger, client, labels, name)

	if err := initRunner(name, plugin.ProtocolVersion, runnerInstance, policyPaths, resultsHelper); err != nil {
		return err
	}

	// TODO: Send failed results to the database?
	// Convert policy_behavior_mapping to proto format for Eval
	// Build mapping from resolved paths to behaviors using helper function
	behaviorMappingWithResolved, unmatchedKeys := buildBehaviorMapping(plugin.PolicyBehavior, ar.policyLocations, plugin.Policies)
	// Log warnings for unmatched keys
	for _, key := range unmatchedKeys {
		fmt.Printf("WARNING: plugin %s policy_behavior key %s does not match any policy path, ignoring\n", name, key)
	}
	// If all keys were unmatched, log a warning and pass empty mapping to prevent false negatives
	if len(behaviorMappingWithResolved) == 0 && len(plugin.PolicyBehavior) > 0 {
		fmt.Printf("WARNING: plugin %s policy_behavior provided but no keys matched any policy path. Passing empty mapping to prevent false negatives.\n", name)
	}
	// Convert to Struct format
	policyBehaviorStruct, err := mapStringSliceToStruct(behaviorMappingWithResolved)
	if err != nil {
		return fmt.Errorf("invalid policy_behavior_mapping for plugin %s: %w", name, err)
	}
	_, err = runnerInstance.Eval(&proto.EvalRequest{
		PolicyPaths:           policyPaths,
		PolicyBehaviorMapping: policyBehaviorStruct,
	}, resultsHelper)

	if err != nil {
		return err
	}

	return nil
}

func (ar *AgentRunner) SendHeartbeat(ctx context.Context, staticAgentUUID uuid.UUID) error {
	config := ar.getConfig()
	client := ar.getAPIClient()
	logger := ar.getLogger()
	logger.Debug("Sending heartbeat via shared API SDK client",
		"uuid", staticAgentUUID.String(),
		"base_url", apiBaseURL(config),
		"auth_enabled", hasAPIAuth(config),
		"client_id", apiClientID(config),
	)
	heartbeatCtx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()
	err := client.Heartbeat.Create(heartbeatCtx, sdktypes.Heartbeat{
		UUID:      staticAgentUUID,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		logger.Error("Error sending heartbeat via SDK", "error", err, "uuid", staticAgentUUID.String())
		return err
	}
	logger.Info("Successfully sent heartbeat to server", "uuid", staticAgentUUID.String())
	return nil
}

type agentEvidenceCreateRequest struct {
	sdktypes.Evidence
	BackMatter *oscalTypes_1_1_3.BackMatter `json:"back-matter,omitempty"`
}

func (ar *AgentRunner) SendAgentRunEvidence(ctx context.Context) error {
	config := ar.getConfig()
	if config == nil || !config.agentEvidenceEnabled() {
		return nil
	}

	logger := ar.getLogger()
	evidence, err := ar.buildAgentRunEvidence(time.Now().UTC())
	if err != nil {
		return err
	}

	payload, err := json.Marshal(evidence)
	if err != nil {
		return err
	}

	evidenceCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := ar.getAPIClient()
	if client == nil {
		return fmt.Errorf("api client is not configured")
	}

	resp, err := client.NewRequest(evidenceCtx, http.MethodPost, "/api/evidence", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode != http.StatusCreated {
		return unexpectedAPIResponseError(resp)
	}

	logger.Info("Successfully sent agent run evidence", "uuid", evidence.UUID.String(), "status", evidence.Status.State)
	return nil
}

func unexpectedAPIResponseError(resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("unexpected nil api response")
	}

	if resp.Body == nil {
		return fmt.Errorf("unexpected api response status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("unexpected api response status code: %d; failed to read response body: %w", resp.StatusCode, err)
	}

	bodyText := strings.TrimSpace(string(body))
	if bodyText == "" {
		return fmt.Errorf("unexpected api response status code: %d", resp.StatusCode)
	}

	return fmt.Errorf("unexpected api response status code: %d: %s", resp.StatusCode, bodyText)
}

func (ar *AgentRunner) buildAgentRunEvidence(now time.Time) (*agentEvidenceCreateRequest, error) {
	config := ar.getConfig()
	interval, err := config.agentEvidenceInterval()
	if err != nil {
		return nil, err
	}

	snapshot := ar.pluginRunSnapshot()
	description := formatAgentEvidenceDescription(snapshot)
	remarks := formatAgentEvidenceRemarks(snapshot)
	labels := agentFoundationalLabels(config)
	evidenceUUID, err := sdk.SeededUUID(labels)
	if err != nil {
		return nil, err
	}

	var expires *time.Time
	if interval > 0 {
		expiry := now.Add(5 * interval)
		expires = &expiry
	}

	state := "satisfied"
	reason := "CCF Agent is capturing evidence correctly."
	if len(snapshot.Failed) > 0 {
		state = "not-satisfied"
		reason = "CCF Agent could not collect evidence from one or more plugins."
	}

	links, backMatter := agentEvidenceErrorArtifacts(snapshot.Errors)
	evidence := &agentEvidenceCreateRequest{
		Evidence: sdktypes.Evidence{
			UUID:        evidenceUUID,
			Title:       "CCF Agent is correctly capturing evidence",
			Description: description,
			Remarks:     &remarks,
			Labels:      labels,
			Start:       now,
			End:         now,
			Expires:     expires,
			Links:       links,
			Status: sdktypes.ObjectiveStatus{
				Reason:  reason,
				Remarks: remarks,
				State:   state,
			},
		},
		BackMatter: backMatter,
	}

	return evidence, nil
}

func formatAgentEvidenceDescription(snapshot pluginRunSnapshot) string {
	if len(snapshot.Failed) > 0 {
		return fmt.Sprintf(
			"ccf-agent could not collect all configured plugin information. Passing plugins: %s. Plugins with errors: %s. Pending plugins: %s.",
			formatPluginList(snapshot.Passing),
			formatPluginList(snapshot.Failed),
			formatPluginList(snapshot.Pending),
		)
	}

	return fmt.Sprintf(
		"ccf-agent plugin collection is healthy. Passing plugins: %s. Plugins with errors: %s. Pending plugins: %s.",
		formatPluginList(snapshot.Passing),
		formatPluginList(snapshot.Failed),
		formatPluginList(snapshot.Pending),
	)
}

func formatAgentEvidenceRemarks(snapshot pluginRunSnapshot) string {
	return strings.Join([]string{
		"Passing plugins: " + formatPluginList(snapshot.Passing),
		"Plugins with errors: " + formatPluginList(snapshot.Failed),
		"Pending plugins: " + formatPluginList(snapshot.Pending),
	}, "\n")
}

func formatPluginList(plugins []string) string {
	if len(plugins) == 0 {
		return "none"
	}

	return strings.Join(plugins, ", ")
}

func agentEvidenceErrorArtifacts(errorsByPlugin map[string]string) ([]sdktypes.Link, *oscalTypes_1_1_3.BackMatter) {
	if len(errorsByPlugin) == 0 {
		return nil, nil
	}

	pluginNames := make([]string, 0, len(errorsByPlugin))
	for pluginName := range errorsByPlugin {
		pluginNames = append(pluginNames, pluginName)
	}
	sort.Strings(pluginNames)

	links := make([]sdktypes.Link, 0, len(pluginNames))
	resources := make([]oscalTypes_1_1_3.Resource, 0, len(pluginNames))
	for _, pluginName := range pluginNames {
		resourceUUID, err := sdk.SeededUUID(map[string]string{
			"type":   "ccf-agent-plugin-error",
			"plugin": pluginName,
		})
		if err != nil {
			resourceUUID = uuid.New()
		}
		title := fmt.Sprintf("%s plugin error", pluginName)
		filename := safePluginErrorFilename(pluginName)
		errorText := truncateAgentEvidenceErrorArtifact(errorsByPlugin[pluginName])

		links = append(links, sdktypes.Link{
			Href:      "#" + resourceUUID.String(),
			Rel:       "describedby",
			MediaType: "text/plain",
			Text:      fmt.Sprintf("Download %s plugin error details", pluginName),
		})
		resources = append(resources, oscalTypes_1_1_3.Resource{
			UUID:        resourceUUID.String(),
			Title:       title,
			Description: fmt.Sprintf("Error reported by ccf-agent while running plugin %s.", pluginName),
			Base64: &oscalTypes_1_1_3.Base64{
				Filename:  filename,
				MediaType: "text/plain",
				Value:     base64.StdEncoding.EncodeToString([]byte(errorText)),
			},
		})
	}

	return links, &oscalTypes_1_1_3.BackMatter{Resources: &resources}
}

func truncateAgentEvidenceErrorArtifact(errorText string) string {
	if len(errorText) <= agentEvidenceErrorArtifactMaxBytes {
		return errorText
	}

	suffix := fmt.Sprintf("\n\n[truncated: plugin error exceeded %d bytes]", agentEvidenceErrorArtifactMaxBytes)
	if len(suffix) >= agentEvidenceErrorArtifactMaxBytes {
		return suffix[:agentEvidenceErrorArtifactMaxBytes]
	}

	return errorText[:agentEvidenceErrorArtifactMaxBytes-len(suffix)] + suffix
}

func safePluginErrorFilename(pluginName string) string {
	var b strings.Builder
	for _, r := range pluginName {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "plugin-error.txt"
	}
	return b.String() + "-error.txt"
}

func (ar *AgentRunner) getRunnerInstance(logger hclog.Logger, path string, protocolVersion int32) (runner.RunnerV2, func(), error) {
	// We're a host! Start by launching the plugin process.
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  runner.HandshakeConfig,
		Plugins:          runner.PluginMap,
		Cmd:              exec.Command(path),
		Logger:           logger,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
	})
	cleanup := ar.trackPluginClient(client)

	// Connect via RPC
	rpcClient, err := client.Client()
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	dispenseName, err := runnerDispenseName(protocolVersion)
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	// Request the plugin
	logger.Debug("Dispensing plugin", "dispense_name", dispenseName)
	raw, err := rpcClient.Dispense(dispenseName)
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	// We should have a Greeter now! This feels like a normal interface
	// implementation but is in fact over an RPC connection.
	runnerInstance, ok := raw.(runner.RunnerV2)
	if !ok {
		cleanup()
		return nil, nil, fmt.Errorf("dispensed plugin %q does not implement runner.RunnerV2", dispenseName)
	}
	return runnerInstance, cleanup, nil
}

// DownloadPlugins checks each item in the config and retrieves the source of the plugin
// building a set of unique sources. It then checks if the source is a path that exists on
// the filesystem, if it isn't, it will download the plugin to the filesystem.
//
// We also update the map of plugin sources, this could be an identity map if it's a local
// file or maps from the URL to the local file if we downloaded a remote file.
//
// We return any errors that occurred during the download process. TODO: What is the right
// error handling here?
func (ar *AgentRunner) DownloadPlugins(ctx context.Context) error {
	logger := ar.getLogger()
	config := ar.getConfig()
	// Build a set of unique plugin sources
	pluginSources := map[string]struct{}{}

	for _, pluginConfig := range config.Plugins {
		pluginSources[pluginConfig.Source] = struct{}{}
	}

	for source := range pluginSources {
		platform := v1.Platform{
			Architecture: runtime.GOARCH,
			OS:           runtime.GOOS,
		}
		out, err := ar.download(ctx, source, AgentPluginDir, "plugin", platformDownloadKey(platform), logger, remote.WithPlatform(platform))

		if err != nil {
			ar.markPluginsWithSourceFailed(source, err)
			return err
		}

		ar.pluginLocations[source] = out
	}

	return nil
}

func (ar *AgentRunner) DownloadPolicies(ctx context.Context) error {
	logger := ar.getLogger()
	config := ar.getConfig()
	// Build a set of unique policy sources
	policySources := map[string]struct{}{}

	for _, pluginConfig := range config.Plugins {
		for _, policy := range pluginConfig.Policies {
			policySources[string(policy)] = struct{}{}
		}
	}

	for source := range policySources {
		out, err := ar.download(ctx, source, AgentPolicyDir, "policies", "", logger)

		if err != nil {
			ar.markPluginsWithPolicyFailed(agentPolicy(source), err)
			return err
		}

		ar.policyLocations[source] = out
	}

	return nil
}

func platformDownloadKey(platform v1.Platform) string {
	return strings.Join([]string{platform.OS, platform.Architecture, platform.Variant}, "/")
}

func (ar *AgentRunner) closePluginClients() {
	logger := ar.getLogger()
	logger.Debug("Cleaning up plugin instances")

	ar.activePluginClientMu.Lock()
	ar.pluginClientsClosing = true
	ar.activePluginClientMu.Unlock()

	for {
		ar.activePluginClientMu.Lock()
		clients := make([]*plugin.Client, 0, len(ar.activePluginClients))
		for client := range ar.activePluginClients {
			clients = append(clients, client)
			delete(ar.activePluginClients, client)
		}
		ar.activePluginClientMu.Unlock()

		if len(clients) == 0 {
			break
		}

		for _, client := range clients {
			client.Kill()
		}
	}

	logger.Debug("Completed plugin cleanup")
}

func (ar *AgentRunner) allowPluginClientTracking() {
	ar.activePluginClientMu.Lock()
	defer ar.activePluginClientMu.Unlock()
	ar.pluginClientsClosing = false
}

func (ar *AgentRunner) trackPluginClient(client *plugin.Client) func() {
	ar.activePluginClientMu.Lock()
	if ar.pluginClientsClosing {
		ar.activePluginClientMu.Unlock()
		client.Kill()
		return func() {}
	}
	ar.activePluginClients[client] = struct{}{}
	ar.activePluginClientMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			ar.activePluginClientMu.Lock()
			delete(ar.activePluginClients, client)
			ar.activePluginClientMu.Unlock()
			client.Kill()
		})
	}
}
