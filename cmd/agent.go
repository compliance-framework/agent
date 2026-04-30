package cmd

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
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
	"github.com/fsnotify/fsnotify"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	ProtocolVersion int32             `mapstructure:"protocol_version"`
	Schedule        *string           `mapstructure:"schedule,omitempty"`
	Source          string            `mapstructure:"source"`
	Policies        []agentPolicy     `mapstructure:"policies"`
	Config          agentPluginConfig `mapstructure:"config"`
	Labels          map[string]string `mapstructure:"labels"`
	protocolSet     bool
}

type agentConfig struct {
	Daemon    bool                    `mapstructure:"daemon"`
	Verbosity int32                   `mapstructure:"verbosity"`
	ApiConfig *apiConfig              `mapstructure:"api"`
	Plugins   map[string]*agentPlugin `mapstructure:"plugins"`
}

// logVerbosity reverses our verbosity "increase" to hclog's reversed "decrease."
// 1 for us means INFO. 1 for hclog means trace.
// 3 for us means TRACE. 3 for hclog means INFO.
// You can see hclog's verbosity here: https://github.com/hashicorp/go-hclog/blob/cb8687c9c619227eac510d0a76d23997fb6667d3/logger.go#L25
func (ac *agentConfig) logVerbosity() int32 {
	return int32(hclog.Info) - ac.Verbosity
}

func (ac *agentConfig) validate() error {
	if len(ac.Plugins) == 0 {
		return fmt.Errorf("no plugins specified in config")
	}

	if err := ac.ApiConfig.validate(); err != nil {
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
	}

	return nil
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
	downloadLocks        sync.Map
	fetchAnnotations     func(ctx context.Context, source string, option ...remote.Option) (map[string]string, error)
	runPluginFunc        func(ctx context.Context, name string, pluginConfig *agentPlugin) error

	queryBundles []*rego.Rego
}

func NewAgentRunner() *AgentRunner {
	return &AgentRunner{
		pluginLocations:     map[string]string{},
		policyLocations:     map[string]string{},
		activePluginClients: map[*plugin.Client]struct{}{},
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

	logger.Debug("Pessimistically downloading plugins and policies to fail early in case daemon runs later.")
	err := ar.DownloadPlugins(ctx)
	if err != nil {
		logger.Error("Error downloading plugins", "error", err)
		return err
	}

	ar.resolvePluginProtocols(ctx)

	err = ar.DownloadPolicies(ctx)
	if err != nil {
		logger.Error("Error downloading policies", "error", err)
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

	// Start the cron and notify readiness
	agentCron.Start()
	heartbeatCron.Start()
	go daemon.SdNotify(false, "READY=1")

	select {
	case sig := <-sigs:
		logger.Info("received signal to terminate plugins and exit", "signal", sig)
		logger.Debug("Stopping crons")
		agentCronStopCtx := agentCron.Stop()
		heartbeatCronStopCtx := heartbeatCron.Stop()
		if !waitForCronStop(daemonCronStopTimeout, agentCronStopCtx, heartbeatCronStopCtx) {
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
		if !waitForCronStop(daemonCronStopTimeout, agentCronStopCtx, heartbeatCronStopCtx) {
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

func (ar *AgentRunner) download(ctx context.Context, source string, outputDir string, binaryPath string, logger hclog.Logger, option ...remote.Option) (string, error) {
	lockKey := strings.Join([]string{outputDir, binaryPath, source}, "\x00")
	lockValue, _ := ar.downloadLocks.LoadOrStore(lockKey, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)

	lock.Lock()
	defer lock.Unlock()

	return internal.Download(ctx, source, outputDir, binaryPath, logger, option...)
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

func (ar *AgentRunner) setupCron(ctx context.Context) (*cron.Cron, error) {
	logger := ar.getLogger()
	parserOptions := cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor
	c := cron.New(cron.WithParser(cron.NewParser(
		parserOptions,
	)), cron.WithChain(cron.SkipIfStillRunning(cronLogger{logger: logger})))
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

		_, err := c.AddFunc(schedule, func() {
			err := runPlugin(ctx, currentPluginName, currentPluginConfig)
			if err != nil {
				// TODO how will we handle these errors ?
				logger.Error("Error running plugin", "plugin", currentPluginName, "error", err, "protocol_version", currentPluginConfig.ProtocolVersion)
			}
		})

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

	for pluginName, pluginConfig := range config.Plugins {
		logger := hclog.New(&hclog.LoggerOptions{
			Name:   fmt.Sprintf("runner.%s", pluginName),
			Output: os.Stdout,
			Level:  hclog.Level(config.logVerbosity()),
		})

		labels := map[string]string{
			"_agent":  "concom",
			"_plugin": pluginName,
		}
		for k, v := range pluginConfig.Labels {
			labels[k] = v
		}

		source := ar.pluginLocations[pluginConfig.Source]

		logger.Debug("Running plugin", "source", source, "protocol_version", pluginConfig.ProtocolVersion)

		if _, err := os.ReadFile(source); err != nil {
			return err
		}

		runnerInstance, cleanupRunner, err := ar.getRunnerInstance(logger, source, pluginConfig.ProtocolVersion)

		if err != nil {
			return err
		}
		if err := func() error {
			defer cleanupRunner()

			_, err = runnerInstance.Configure(&proto.ConfigureRequest{
				Config: pluginConfig.Config,
			})
			if err != nil {
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
			_, err = runnerInstance.Eval(&proto.EvalRequest{
				PolicyPaths: policyPaths,
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
			return err
		}
	}

	return nil
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
		policyLocation, err := ar.download(ctx, string(inputBundle), AgentPolicyDir, "policies", logger)
		if err != nil {
			return err
		}
		policyPaths = append(policyPaths, policyLocation)
	}

	pluginExecutable, err := ar.download(ctx, plugin.Source, AgentPluginDir, "plugin", logger, remote.WithPlatform(v1.Platform{
		Architecture: runtime.GOARCH,
		OS:           runtime.GOOS,
	}))

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

	labels := map[string]string{
		"_agent":  "concom",
		"_plugin": name,
	}
	for k, v := range plugin.Labels {
		labels[k] = v
	}

	pluginLogger.Debug("Running plugin", "source", pluginExecutable, "protocol_version", plugin.ProtocolVersion)

	if _, err := os.ReadFile(pluginExecutable); err != nil {
		return err
	}

	runnerInstance, cleanupRunner, err := ar.getRunnerInstance(pluginLogger, pluginExecutable, plugin.ProtocolVersion)

	if err != nil {
		return err
	}
	defer cleanupRunner()

	_, err = runnerInstance.Configure(&proto.ConfigureRequest{
		Config: plugin.Config,
	})
	if err != nil {
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
	_, err = runnerInstance.Eval(&proto.EvalRequest{
		PolicyPaths: policyPaths,
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
		out, err := ar.download(ctx, source, AgentPluginDir, "plugin", logger, remote.WithPlatform(v1.Platform{
			Architecture: runtime.GOARCH,
			OS:           runtime.GOOS,
		}))

		if err != nil {
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
		out, err := ar.download(ctx, source, AgentPolicyDir, "policies", logger)

		if err != nil {
			return err
		}

		ar.policyLocations[source] = out
	}

	return nil
}

func (ar *AgentRunner) closePluginClients() {
	logger := ar.getLogger()
	logger.Debug("Cleaning up plugin instances")

	ar.activePluginClientMu.Lock()
	clients := make([]*plugin.Client, 0, len(ar.activePluginClients))
	for client := range ar.activePluginClients {
		clients = append(clients, client)
		delete(ar.activePluginClients, client)
	}
	ar.activePluginClientMu.Unlock()

	for _, client := range clients {
		client.Kill()
	}

	logger.Debug("Completed plugin cleanup")
}

func (ar *AgentRunner) trackPluginClient(client *plugin.Client) func() {
	ar.activePluginClientMu.Lock()
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
