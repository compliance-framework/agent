package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/compliance-framework/agent/internal"
	"github.com/compliance-framework/agent/internal/agentstate"
	"github.com/compliance-framework/agent/internal/pluginlib"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/sdk"
	sdktypes "github.com/compliance-framework/api/sdk/types"
	"github.com/coreos/go-systemd/v22/daemon"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/spf13/cobra"
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
	Config          agentPluginConfig      `mapstructure:"config"`
	Labels          map[string]string      `mapstructure:"labels"`
	PolicyData      map[string]interface{} `mapstructure:"policy_data,omitempty"`
	PolicyBehavior  map[string][]string    `mapstructure:"policy_behavior,omitempty"`
	protocolSet     bool
}

type agentEvidenceConfig struct {
	Enabled             *bool  `mapstructure:"enabled,omitempty"`
	EmitOnRunCompletion *bool  `mapstructure:"emit_on_run_completion,omitempty"`
	Interval            string `mapstructure:"interval,omitempty"`
}

// agentConfig is the RUNTIME form of the configuration, built from the declared form
// (agentconfig.Config) by toRuntime. It is immutable once handed to AgentRunner.UpdateConfig,
// except for the protocol resolution AgentRunner.Run performs on its own copy and the sync
// metadata, which the reconciler may update atomically when a new revision leaves the
// effective configuration unchanged.
type agentConfig struct {
	Daemon        bool                    `mapstructure:"daemon"`
	Verbosity     int32                   `mapstructure:"verbosity"`
	ApiConfig     *apiConfig              `mapstructure:"api"`
	Plugins       map[string]*agentPlugin `mapstructure:"plugins"`
	AgentEvidence *agentEvidenceConfig    `mapstructure:"agent_evidence"`

	// inlinePolicyDirs maps "inline:<name>" policy entries to the path plugins receive: the
	// bundle's stable path, which the reconciler points at inlineTrees before each run (R67).
	inlinePolicyDirs map[string]string
	// inlineTrees maps "inline:<name>" policy entries to their materialized, content-addressed
	// tree (inlinepolicy.Materialized.Dir).
	inlineTrees map[string]string
	// inlineDigests maps "inline:<name>" policy entries to their tree digest, the evidence
	// _policy_digest fallback when a bundle's artifact digest is not known.
	inlineDigests map[string]string
	// sync is what the heartbeat reports about the applied remote configuration (R11, R45).
	// Read it with syncInfo; nil means the zero syncMeta.
	sync *atomic.Pointer[syncMeta]
	// remote is the normalized remote_config block.
	remote agentconfig.RemoteConfig
}

// syncMeta describes the applied remote configuration.
type syncMeta struct {
	AppliedRevision int64  // 0 when running the file only
	Digest          string // agentconfig.Digest of the effective declared config
	Mode            string // remote_config.mode
}

// syncInfo returns the sync metadata (safe for concurrent use with setSync).
func (ac *agentConfig) syncInfo() syncMeta {
	if ac == nil || ac.sync == nil {
		return syncMeta{}
	}
	if p := ac.sync.Load(); p != nil {
		return *p
	}
	return syncMeta{}
}

// setSync stores the sync metadata. The first call must happen before the config is shared.
func (ac *agentConfig) setSync(m syncMeta) {
	if ac.sync == nil {
		ac.sync = &atomic.Pointer[syncMeta]{}
	}
	ac.sync.Store(&m)
}

// logVerbosity maps our verbosity "increase" onto hclog's levels: our 0/1/2 = Info/Debug/Trace,
// i.e. hclog.Level(Info - v). See hclog's levels here:
// https://github.com/hashicorp/go-hclog/blob/cb8687c9c619227eac510d0a76d23997fb6667d3/logger.go#L25
func (ac *agentConfig) logVerbosity() int32 {
	return int32(hclog.Info) - ac.Verbosity
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

// CCFPropNamespace is the OSCAL prop namespace of CCF props.
const CCFPropNamespace = "https://compliance-framework.github.io/ns"

// configRevisionPropName stamps evidence with the applied remote configuration revision (R38).
const configRevisionPropName = "agent-config-revision"

// daemonCronStopTimeout bounds the cron stop on SIGINT/SIGTERM before plugins are killed,
// also when the signal arrives during a reload drain (R33).
var daemonCronStopTimeout = 30 * time.Second

// reloadDrainTimeout bounds how long in-flight plugin runs may finish when a new
// configuration replaces the running one (R33). SIGTERM keeps daemonCronStopTimeout.
var reloadDrainTimeout = 5 * time.Minute

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
	agentCmd.Flags().BoolP("daemon", "d", false, "Specify to run as a long running daemon")

	agentCmd.Flags().StringP("config", "c", "", "Location of config file")
	agentCmd.MarkFlagRequired("config")

	agentCmd.Flags().String("state-dir", "", "Directory for this instance's state (instance ID, remote config cache, inline policies); overrides CCF_STATE_DIR. Default: .compliance-framework/state/<hash of the config path>")
	agentCmd.Flags().String("instance-id", "", "Pin this instance's UUID (not persisted); overrides CCF_INSTANCE_ID")

	return agentCmd
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

func initRunner(name string, protocolVersion int32, runnerInstance runner.RunnerV2, policyPaths []string, policyBehavior map[string]*proto.StringList, resultsHelper runner.ApiHelper) error {
	if protocolVersion <= DefaultProtocolVersion {
		return nil
	}

	_, err := runnerInstance.Init(&proto.InitRequest{
		PolicyPaths:    policyPaths,
		PolicyBehavior: policyBehavior,
	}, resultsHelper)
	if err == nil {
		return nil
	}

	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("plugin %s configured as protocol_version=%d but does not implement Init", name, protocolVersion)
	}

	return err
}

func configureRunner(name string, runnerInstance runner.RunnerV2, config agentPluginConfig, policyData map[string]interface{}, policyBehavior map[string][]string) error {
	policyDataStruct, err := mapToStruct(policyData)
	if err != nil {
		return fmt.Errorf("invalid policy_data for plugin %s: %w", name, err)
	}

	_, err = runnerInstance.Configure(&proto.ConfigureRequest{
		Config:         config,
		PolicyData:     policyDataStruct,
		PolicyBehavior: policyBehaviorToProto(policyBehavior),
	})
	return err
}

// Main the entrypoint for the `agent` command
//
// It will read the configuration file, and then run the agent. Various command line flags can
// be used to override the config file.
func agentRunner(cmd *cobra.Command, args []string) error {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "agent",
		Output: os.Stdout,
		Level:  hclog.Debug,
	})

	configPath, err := filepath.Abs(cmd.Flag("config").Value.String())
	if err != nil {
		return err
	}

	stateDir, stateDirSource, err := stateDirFrom(cmd, configPath)
	if err != nil {
		return err
	}
	idOverride, err := instanceIDOverride(cmd)
	if err != nil {
		return err
	}
	store := agentstate.Open(stateDir, logger)
	id, persisted := store.InstanceID(idOverride)
	// R52: the default state dir depends on the absolute config path, so moving the config
	// file silently creates a new instance. Say where state lives.
	logger.Info("Agent state", "state_dir", stateDir, "state_dir_source", stateDirSource, "instance_id", id.String(), "instance_id_persisted", persisted)

	// One artifact uploader for the process: the reconciler's policy tree uploads and every
	// plugin run's evidence artifacts share what each API already has (R62).
	artifacts := runner.NewArtifactUploader()
	ar := NewAgentRunner(WithInstanceID(id), WithSharedArtifactUploader(artifacts))
	rc := newReconciler(cmd, configPath, store, ar, logger)
	rc.instanceID = id
	rc.artifacts = artifacts
	rc.resolvePolicy = func(ctx context.Context, source string) (string, error) {
		return ar.downloadPolicy(ctx, source, logger)
	}
	pluginLibs := &pluginlib.Cache{}
	rc.pluginLib = func(ctx context.Context, source string) (string, error) {
		binary, err := ar.downloadPlugin(ctx, source, logger)
		if err != nil {
			return "", err
		}
		return pluginLibs.Version(binary)
	}
	rc.onStartupFailure = ar.ReportStartupFailure

	active, err := rc.startup(context.Background())
	if err != nil {
		// An unusable local configuration at startup exits 1, as it always has.
		return err
	}

	rootCtx, stopLoop := context.WithCancel(context.Background())
	defer stopLoop()
	if active.runtime.Daemon {
		defer rc.watchFile()()
		go rc.loop(rootCtx)
	}

	return rc.run(active, func(ctx context.Context, cfg *agentConfig) error {
		ar.UpdateConfig(cfg)
		return ar.Run(ctx)
	})
}

// stateDirFrom resolves the state directory: --state-dir, then CCF_STATE_DIR, then the
// default derived from the absolute config path (R31). It also returns where it came from.
func stateDirFrom(cmd *cobra.Command, configPath string) (dir string, source string, err error) {
	if flag := cmd.Flags().Lookup("state-dir"); flag != nil && strings.TrimSpace(flag.Value.String()) != "" {
		dir, err = filepath.Abs(strings.TrimSpace(flag.Value.String()))
		return dir, "flag", err
	}
	if env := strings.TrimSpace(os.Getenv("CCF_STATE_DIR")); env != "" {
		dir, err = filepath.Abs(env)
		return dir, "env", err
	}
	dir, err = agentstate.DefaultDir(configPath)
	return dir, "default(config-path)", err
}

// instanceIDOverride returns --instance-id or CCF_INSTANCE_ID. An override that is not a
// UUID is an error: silently ignoring it would register a different instance.
func instanceIDOverride(cmd *cobra.Command) (string, error) {
	value, source := "", ""
	if flag := cmd.Flags().Lookup("instance-id"); flag != nil && strings.TrimSpace(flag.Value.String()) != "" {
		value, source = strings.TrimSpace(flag.Value.String()), "--instance-id"
	} else if env := strings.TrimSpace(os.Getenv("CCF_INSTANCE_ID")); env != "" {
		value, source = env, "CCF_INSTANCE_ID"
	}
	if value == "" {
		return "", nil
	}
	if _, err := uuid.Parse(value); err != nil {
		return "", fmt.Errorf("%s must be a UUID: %w", source, err)
	}
	return value, nil
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
	sendHeartbeatFunc    func(ctx context.Context, instanceID uuid.UUID) error
	// notifySignals and exitFunc are test seams over signal.Notify(SIGINT, SIGTERM) and
	// os.Exit (nil = the real ones).
	notifySignals func(c chan<- os.Signal)
	exitFunc      func(code int)

	pluginRunMu                   sync.RWMutex
	pluginRuns                    map[string]pluginRunRecord
	firstAgentEvidenceSendStarted bool

	// instanceID is this agent instance's stable ID (R31); set once at construction.
	instanceID uuid.UUID
	// artifacts is the process-wide artifact uploader, shared with the reconciler (R62).
	artifacts *runner.ArtifactUploader

	// protocolCache maps a plugin source to the protocol version its OCI annotations
	// declared. It survives reloads so a registry outage during a reload cannot silently
	// turn a v2 plugin into v1 (R32).
	protocolCacheMu sync.Mutex
	protocolCache   map[string]int32
}

// AgentRunnerOption configures an AgentRunner.
type AgentRunnerOption func(*AgentRunner)

// WithInstanceID sets the instance ID the heartbeat and config reports use.
func WithInstanceID(id uuid.UUID) AgentRunnerOption {
	return func(ar *AgentRunner) { ar.instanceID = id }
}

// WithSharedArtifactUploader makes every plugin run upload through u (R62).
func WithSharedArtifactUploader(u *runner.ArtifactUploader) AgentRunnerOption {
	return func(ar *AgentRunner) { ar.artifacts = u }
}

func NewAgentRunner(opts ...AgentRunnerOption) *AgentRunner {
	ar := &AgentRunner{
		pluginLocations:     map[string]string{},
		policyLocations:     map[string]string{},
		activePluginClients: map[*plugin.Client]struct{}{},
		pluginRuns:          map[string]pluginRunRecord{},
		fetchAnnotations:    internal.GetAnnotations,
		httpClient:          http.DefaultClient,
		instanceID:          uuid.New(),
		protocolCache:       map[string]int32{},
		artifacts:           runner.NewArtifactUploader(),
	}
	for _, opt := range opts {
		opt(ar)
	}
	return ar
}

// InstanceID returns the instance ID.
func (ar *AgentRunner) InstanceID() uuid.UUID { return ar.instanceID }

func (ar *AgentRunner) UpdateConfig(config *agentConfig) {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "agent-runner",
		Output: os.Stdout,
		Level:  hclog.Level(config.logVerbosity()),
	})

	ar.stateMu.Lock()
	// Reuse the SDK client when the api block is unchanged, so its token cache survives
	// overlay reloads.
	client := ar.apiClient
	if client == nil || ar.config == nil || !reflect.DeepEqual(ar.config.ApiConfig, config.ApiConfig) {
		client = ar.buildAPIClient(config, logger)
	}
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

func policyBehaviorToProto(policyBehavior map[string][]string) map[string]*proto.StringList {
	if len(policyBehavior) == 0 {
		return nil
	}
	result := make(map[string]*proto.StringList, len(policyBehavior))
	for key, values := range policyBehavior {
		if values == nil {
			result[key] = nil
			continue
		}
		result[key] = &proto.StringList{Values: append([]string(nil), values...)}
	}
	return result
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

	if config.Daemon {
		return ar.runDaemon(ctx)
	}

	return ar.runAllPlugins(ctx)
}

func (ar *AgentRunner) resolvePluginProtocols(ctx context.Context) {
	ar.resolveProtocolsFor(ctx, ar.getConfig(), ar.getLogger())
}

// resolveProtocolsFor sets the protocol version of every implicit-protocol OCI plugin in config
// from its annotations, consulting protocolCache first. Only a cache miss fetches annotations.
func (ar *AgentRunner) resolveProtocolsFor(ctx context.Context, config *agentConfig, logger hclog.Logger) {
	if ctx == nil {
		ctx = context.Background()
	}
	if config == nil {
		return
	}
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	for pluginName, pluginConfig := range config.Plugins {
		if pluginConfig == nil || pluginConfig.protocolSet || !internal.IsOCI(pluginConfig.Source) {
			continue
		}

		ar.protocolCacheMu.Lock()
		cached, hit := ar.protocolCache[pluginConfig.Source]
		ar.protocolCacheMu.Unlock()
		if hit {
			pluginConfig.ProtocolVersion = cached
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
			ar.protocolCacheMu.Lock()
			ar.protocolCache[pluginConfig.Source] = protocolVersion
			ar.protocolCacheMu.Unlock()
		}()
	}
}

// runDaemon runs the plugin crons until ctx is cancelled (a reload: in-flight runs drain for
// up to reloadDrainTimeout, R33) or the process receives SIGINT/SIGTERM (exit). Setup errors
// are returned rather than exiting the process.
func (ar *AgentRunner) runDaemon(ctx context.Context) error {
	logger := ar.getLogger()
	sigs := make(chan os.Signal, 1)
	ar.signalNotify(sigs)
	defer signal.Stop(sigs)

	agentCron, err := ar.setupCron(ctx)
	if err != nil {
		logger.Error("Error setting up agent cron", "error", err)
		return err
	}

	heartbeatCron, err := ar.setupHeartbeatCron(ctx)
	if err != nil {
		logger.Error("Error setting up heartbeat", "error", err)
		return err
	}
	agentEvidenceCron, err := ar.setupAgentEvidenceCron(ctx)
	if err != nil {
		logger.Error("Error setting up agent evidence", "error", err)
		return err
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
		ar.exitProcess(0)
		return nil
	case <-ctx.Done():
		logger.Debug("received cancel signal to return from daemon")
		logger.Debug("Stopping crons")
		agentCronStopCtx := agentCron.Stop()
		heartbeatCronStopCtx := heartbeatCron.Stop()
		agentEvidenceCronStopCtx := agentEvidenceCron.Stop()
		drained, sig := waitForCronStopOrSignal(reloadDrainTimeout, sigs, agentCronStopCtx, heartbeatCronStopCtx, agentEvidenceCronStopCtx)
		if sig != nil {
			// A SIGINT/SIGTERM during the reload drain is not lost: it keeps its 30s (R33).
			logger.Info("received signal during the reload drain; terminating plugins and exiting", "signal", sig)
			if !waitForCronStop(daemonCronStopTimeout, agentCronStopCtx, heartbeatCronStopCtx, agentEvidenceCronStopCtx) {
				logger.Warn("Timed out waiting for cron jobs to stop before plugin cleanup", "timeout", daemonCronStopTimeout)
			}
			ar.closePluginClients()
			logger.Debug("Exiting")
			ar.exitProcess(0)
			return nil
		}
		if !drained {
			logger.Warn("Timed out waiting for in-flight plugin runs to drain before reload", "timeout", reloadDrainTimeout)
		}
		logger.Debug("Shutting down plugins")
		ar.closePluginClients()
		return nil
	}
}

func (ar *AgentRunner) signalNotify(c chan<- os.Signal) {
	if ar.notifySignals != nil {
		ar.notifySignals(c)
		return
	}
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
}

func (ar *AgentRunner) exitProcess(code int) {
	if ar.exitFunc != nil {
		ar.exitFunc(code)
		return
	}
	os.Exit(code)
}

func waitForCronStop(timeout time.Duration, stopContexts ...context.Context) bool {
	done, _ := waitForCronStopOrSignal(timeout, nil, stopContexts...)
	return done
}

// waitForCronStopOrSignal waits until every stop context is done (true), the timeout expires
// (false) or a signal arrives on sigs (false and the signal; a nil sigs never fires).
func waitForCronStopOrSignal(timeout time.Duration, sigs <-chan os.Signal, stopContexts ...context.Context) (bool, os.Signal) {
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
		return true, nil
	case sig := <-sigs:
		return false, sig
	case <-timer.C:
		select {
		case <-allDone:
			return true, nil
		default:
			return false, nil
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
	staticAgentUUID := ar.instanceID
	sendHeartbeat := ar.SendHeartbeat
	if ar.sendHeartbeatFunc != nil {
		sendHeartbeat = ar.sendHeartbeatFunc
	}
	_, err := c.AddFunc(fmt.Sprintf("%d * * * * *", staggeredSeconds), func() {
		err := sendHeartbeat(ctx, staticAgentUUID)
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
	// Each job runs with the config, API client and logger of THIS setup: a job still running
	// when a reload's drain times out must not pick up the next configuration's state.
	snap := ar.snapshot()
	runPlugin := func(ctx context.Context, name string, plugin *agentPlugin) error {
		return ar.runPluginWith(ctx, snap, name, plugin)
	}
	if ar.runPluginFunc != nil {
		runPlugin = ar.runPluginFunc
	}
	// Plugin runs are not cut short by a reload: runDaemon stops the cron and lets in-flight
	// runs drain for up to reloadDrainTimeout (R33) before killing the plugin processes.
	jobCtx := context.WithoutCancel(ctx)

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
			err := runPlugin(jobCtx, currentPluginName, currentPluginConfig)
			ar.markPluginRunFinished(currentPluginName, err)
			if err != nil {
				// TODO how will we handle these errors ?
				jobLogger.Error("Error running plugin", "error", err, "protocol_version", currentPluginConfig.ProtocolVersion)
			}
			if ar.reserveFirstAgentEvidenceSend() {
				if evidenceErr := ar.SendAgentRunEvidence(jobCtx); evidenceErr != nil {
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

			if err := configureRunner(pluginName, runnerInstance, pluginConfig.Config, pluginConfig.PolicyData, pluginConfig.PolicyBehavior); err != nil {
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
			policySources := make(map[string]runner.Source, len(pluginConfig.Policies))

			for _, inputBundle := range pluginConfig.Policies {
				policyLocation := ar.policyLocations[string(inputBundle)]
				policyPaths = append(policyPaths, policyLocation)
				policySources[policyLocation] = config.policySource(string(inputBundle), policyLocation)
			}

			// Create a new results helper for the plugin to send results back to
			logger.Debug("Creating plugin API helper",
				"plugin", pluginName,
				"auth_enabled", hasAPIAuth(config),
				"client_id", apiClientID(config),
			)
			resultsHelper := runner.NewApiHelper(logger, client, labels, pluginName,
				runner.WithPolicyPaths(policyPaths),
				runner.WithSources(sourceOf(pluginConfig.Source, source), policySources),
				runner.WithArtifactUploader(ar.artifacts, apiBaseURL(config)),
				runner.WithEvidenceProps(configRevisionProps(config)...),
			)

			policyBehaviorProto := policyBehaviorToProto(pluginConfig.PolicyBehavior)
			if err := initRunner(pluginName, pluginConfig.ProtocolVersion, runnerInstance, policyPaths, policyBehaviorProto, resultsHelper); err != nil {
				return err
			}

			// TODO: Send failed results to the database?
			_, err = runnerInstance.Eval(&proto.EvalRequest{
				PolicyPaths:    policyPaths,
				PolicyBehavior: policyBehaviorProto,
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

// runSnapshot is the state one plugin run uses from start to end.
type runSnapshot struct {
	config *agentConfig
	client *sdk.Client
	logger hclog.Logger
}

func (ar *AgentRunner) snapshot() runSnapshot {
	return runSnapshot{config: ar.getConfig(), client: ar.getAPIClient(), logger: ar.getLogger()}
}

// runPluginWith runs one plugin once with the state in snap.
//
// Returns:
// - error: any error that occurred during the run
func (ar *AgentRunner) runPluginWith(ctx context.Context, snap runSnapshot, name string, plugin *agentPlugin) error {
	config, client, logger := snap.config, snap.client, snap.logger
	logger.Debug("Running single plugin with shared API SDK client",
		"plugin", name,
		"auth_enabled", hasAPIAuth(config),
		"client_id", apiClientID(config),
	)

	policyPaths := make([]string, 0)
	policySources := make(map[string]runner.Source, len(plugin.Policies))
	for _, inputBundle := range plugin.Policies {
		if dir, ok := config.inlinePolicyDirs[string(inputBundle)]; ok {
			policyPaths = append(policyPaths, dir)
			policySources[dir] = config.policySource(string(inputBundle), dir)
			continue
		}
		policyLocation, err := ar.download(ctx, string(inputBundle), AgentPolicyDir, "policies", "", logger)
		if err != nil {
			return err
		}
		policyPaths = append(policyPaths, policyLocation)
		policySources[policyLocation] = config.policySource(string(inputBundle), policyLocation)
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

	if err := configureRunner(name, runnerInstance, plugin.Config, plugin.PolicyData, plugin.PolicyBehavior); err != nil {
		return err
	}

	// Create a new results helper for the plugin to send results back to
	pluginLogger.Debug("Creating plugin API helper",
		"plugin", name,
		"auth_enabled", hasAPIAuth(config),
		"client_id", apiClientID(config),
	)
	resultsHelper := runner.NewApiHelper(pluginLogger, client, labels, name,
		runner.WithPolicyPaths(policyPaths),
		runner.WithSources(sourceOf(plugin.Source, pluginExecutable), policySources),
		runner.WithArtifactUploader(ar.artifacts, apiBaseURL(config)),
		runner.WithEvidenceProps(configRevisionProps(config)...),
	)

	policyBehaviorProto := policyBehaviorToProto(plugin.PolicyBehavior)
	if err := initRunner(name, plugin.ProtocolVersion, runnerInstance, policyPaths, policyBehaviorProto, resultsHelper); err != nil {
		return err
	}

	// TODO: Send failed results to the database?
	_, err = runnerInstance.Eval(&proto.EvalRequest{
		PolicyPaths:    policyPaths,
		PolicyBehavior: policyBehaviorProto,
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
	err := client.Heartbeat.Create(heartbeatCtx, buildHeartbeat(config, staticAgentUUID, time.Now().UTC()))
	if err != nil {
		logger.Error("Error sending heartbeat via SDK", "error", err, "uuid", staticAgentUUID.String())
		return err
	}
	logger.Info("Successfully sent heartbeat to server", "uuid", staticAgentUUID.String())
	return nil
}

// configRevisionProps returns the evidence prop naming the applied overlay revision, or nil
// when the agent runs the file only (R38).
func configRevisionProps(config *agentConfig) []sdktypes.Property {
	meta := config.syncInfo()
	if meta.AppliedRevision <= 0 {
		return nil
	}
	return []sdktypes.Property{{
		Ns:    CCFPropNamespace,
		Name:  configRevisionPropName,
		Value: strconv.FormatInt(meta.AppliedRevision, 10),
	}}
}

// buildHeartbeat builds the heartbeat body. When remote configuration is not off it carries
// the applied revision (0 when running the file only, never null) and the effective digest,
// which lets the API create the instance row (R11, R45).
func buildHeartbeat(config *agentConfig, id uuid.UUID, now time.Time) sdktypes.Heartbeat {
	hb := sdktypes.Heartbeat{UUID: id, CreatedAt: now}
	if meta := config.syncInfo(); meta.Mode != "" && meta.Mode != agentconfig.ModeOff {
		rev := meta.AppliedRevision
		hb.ConfigRevision = &rev
		hb.ConfigDigest = meta.Digest
	}
	return hb
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
			Props:       configRevisionProps(config),
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
	cmd := exec.Command(path)
	// Plugins get the host environment minus the agent's own API credentials (R26); go-plugin
	// would otherwise append the whole environment.
	cmd.Env = pluginEnviron(os.Environ())
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  runner.HandshakeConfig,
		Plugins:          runner.PluginMap,
		Cmd:              cmd,
		SkipHostEnv:      true,
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
		// Inline bundles were materialized by the reconciler; they are never downloaded.
		if dir, ok := config.inlinePolicyDirs[source]; ok {
			ar.policyLocations[source] = dir
			continue
		}
		out, err := ar.download(ctx, source, AgentPolicyDir, "policies", "", logger)

		if err != nil {
			ar.markPluginsWithPolicyFailed(agentPolicy(source), err)
			return err
		}

		ar.policyLocations[source] = out
	}

	return nil
}

// pluginEnviron returns environ without the variables whose name starts with CCF_API_AUTH_
// (case-insensitive), so plugins never see the agent's API credentials (R26).
func pluginEnviron(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(strings.ToUpper(name), "CCF_API_AUTH_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// Prefetch downloads every plugin and (non-inline) policy source of cfg and resolves plugin
// protocol versions, WITHOUT touching the running configuration's pluginLocations or
// policyLocations. The reconciler calls it before cancelling the running configuration, so a
// download failure never tears down a working agent (prepare-then-cancel, R32).
func (ar *AgentRunner) Prefetch(ctx context.Context, cfg *agentConfig) error {
	logger := ar.getLogger()
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	pluginSources := map[string]struct{}{}
	policySources := map[string]struct{}{}
	for _, pluginConfig := range cfg.Plugins {
		pluginSources[pluginConfig.Source] = struct{}{}
		for _, policy := range pluginConfig.Policies {
			if _, inline := cfg.inlinePolicyDirs[string(policy)]; inline {
				continue
			}
			policySources[string(policy)] = struct{}{}
		}
	}
	for _, source := range sortedSetKeys(pluginSources) {
		if _, err := ar.downloadPlugin(ctx, source, logger); err != nil {
			return &downloadError{source: source, err: err}
		}
	}
	ar.resolveProtocolsFor(ctx, cfg, logger)
	for _, source := range sortedSetKeys(policySources) {
		if _, err := ar.downloadPolicy(ctx, source, logger); err != nil {
			return &downloadError{source: source, policy: true, err: err}
		}
	}
	return nil
}

// downloadError is a Prefetch failure: which plugin or policy source could not be fetched.
type downloadError struct {
	source string
	policy bool
	err    error
}

func (e *downloadError) Error() string {
	kind := "plugin"
	if e.policy {
		kind = "policy"
	}
	return fmt.Sprintf("download %s %s: %v", kind, e.source, e.err)
}

func (e *downloadError) Unwrap() error { return e.err }

// ReportStartupFailure records that the configuration the agent starts with could not be
// downloaded, exactly as Run always has on a startup download failure: the plugins using the
// failed source are marked failed and the startup-failure agent evidence is sent (when agent
// evidence and emit_on_run_completion are enabled). The agent then exits 1.
func (ar *AgentRunner) ReportStartupFailure(ctx context.Context, cfg *agentConfig, err error) {
	ar.UpdateConfig(cfg)
	var dl *downloadError
	switch {
	case errors.As(err, &dl) && dl.policy:
		ar.markPluginsWithPolicyFailed(agentPolicy(dl.source), dl.err)
	case errors.As(err, &dl):
		ar.markPluginsWithSourceFailed(dl.source, dl.err)
	}
	logger := ar.getLogger()
	logger.Error("Error downloading plugins and policies", "error", err)
	if evidenceErr := ar.sendAgentRunEvidenceOnStartupFailure(ctx); evidenceErr != nil {
		logger.Error("Error sending agent run evidence", "error", evidenceErr)
	}
}

// downloadPlugin returns the plugin binary of source for this platform, downloading it into
// the shared plugin cache when it is not there yet. Prefetch uses it, so the reconciler's
// plugin library check (R76) reads the binary Prefetch fetched.
func (ar *AgentRunner) downloadPlugin(ctx context.Context, source string, logger hclog.Logger) (string, error) {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	platform := v1.Platform{
		Architecture: runtime.GOARCH,
		OS:           runtime.GOOS,
	}
	return ar.download(ctx, source, AgentPluginDir, "plugin", platformDownloadKey(platform), logger, remote.WithPlatform(platform))
}

// downloadPolicy fetches one policy source into the shared policy cache.
func (ar *AgentRunner) downloadPolicy(ctx context.Context, source string, logger hclog.Logger) (string, error) {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	return ar.download(ctx, source, AgentPolicyDir, "policies", "", logger)
}

func sortedSetKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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

// sourceOf describes where a plugin or policy bundle came from, for evidence: its configured
// source and, where known, the digest of what the agent extracted at location.
func sourceOf(source, location string) runner.Source {
	return runner.Source{Reference: source, Digest: internal.SourceDigest(source, location)}
}

// policySource describes where the policy entry, which plugins receive at location, came from.
// An inline bundle is recorded as its entry (inline:<name>) with its artifact digest, or its
// tree digest when the evaluation could not store the bundle; location is then the bundle's
// stable path (R67), the same key the plugin reports evaluations under.
func (c *agentConfig) policySource(entry, location string) runner.Source {
	if _, inline := c.inlinePolicyDirs[entry]; inline {
		return runner.Source{Reference: entry, Digest: c.inlineDigests[entry], BundleArtifact: true}
	}
	return sourceOf(entry, location)
}
