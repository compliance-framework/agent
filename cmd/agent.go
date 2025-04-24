package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/compliance-framework/agent/internal"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/compliance-framework/gooci/pkg/oci"
	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/fsnotify/fsnotify"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type apiConfig struct {
	Url string `json:"url"`
}

type agentPolicy string

type agentPlugin struct {
	Schedule *string                `mapstructure:"schedule,omitempty"`
	Source   string                 `mapstructure:"source"`
	Policies []agentPolicy          `mapstructure:"policies"`
	Config   map[string]interface{} `mapstructure:"config"`
	Labels   map[string]string      `mapstructure:"labels"`
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

	if ac.ApiConfig == nil {
		return fmt.Errorf("no api config specified in config")
	}

	return nil
}

const AgentPluginDir = ".compliance-framework/plugins"
const AgentPolicyDir = ".compliance-framework/policies"

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

	return config, nil
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
	logger hclog.Logger
	mu     sync.Mutex
	config *agentConfig

	pluginLocations map[string]string
	policyLocations map[string]string

	queryBundles []*rego.Rego
}

func NewAgentRunner() *AgentRunner {
	return &AgentRunner{
		pluginLocations: map[string]string{},
		policyLocations: map[string]string{},
	}
}

func (ar *AgentRunner) UpdateConfig(config *agentConfig) {
	ar.config = config
	ar.logger = hclog.New(&hclog.LoggerOptions{
		Name:   "agent-runner",
		Output: os.Stdout,
		Level:  hclog.Level(config.logVerbosity()),
	})
}

func (ar *AgentRunner) Run(ctx context.Context) error {
	ar.logger.Info("Starting agent", "daemon", ar.config.Daemon)

	ar.logger.Debug("Pessimistically downloading plugins and policies to fail early in case daemon runs later.")
	err := ar.DownloadPlugins(ctx)
	if err != nil {
		ar.logger.Error("Error downloading plugins", "error", err)
		return err
	}

	err = ar.DownloadPolicies(ctx)
	if err != nil {
		ar.logger.Error("Error downloading policies", "error", err)
		return err
	}
	ar.logger.Debug("Pessimistically downloading plugins and policies worked successfully. Starting the agent.")

	if ar.config.Daemon == true {
		ar.runDaemon(ctx)
		return nil
	}

	return ar.runAllPlugins(ctx)
}

// Should never return, either handles any error or panics.
func (ar *AgentRunner) runDaemon(ctx context.Context) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	agentCron, err := ar.setupCron(ctx)
	if err != nil {
		ar.logger.Error("Error setting up agent cron", "error", err)
		os.Exit(1)
	}

	heartbeatCron, err := ar.setupHeartbeatCron(ctx)
	if err != nil {
		ar.logger.Error("Error setting up heartbeat", "error", err)
		os.Exit(1)
	}

	// Start the cron and notify readiness
	agentCron.Start()
	heartbeatCron.Start()
	go daemon.SdNotify(false, "READY=1")

	select {
	case sig := <-sigs:
		ar.logger.Info("received signal to terminate plugins and exit", "signal", sig)
		ar.logger.Debug("Shutting down plugins")
		ar.closePluginClients()
		ar.logger.Debug("Stopping crons")
		agentCron.Stop()
		heartbeatCron.Stop()
		ar.logger.Debug("Exiting")
		os.Exit(0)
	case <-ctx.Done():
		ar.logger.Debug("received cancel signal to return from daemon")
		ar.logger.Debug("Shutting down plugins")
		ar.closePluginClients()
		ar.logger.Debug("Stopping crons")
		agentCron.Stop()
		heartbeatCron.Stop()
		return
	}
}

func (ar *AgentRunner) setupHeartbeatCron(ctx context.Context) (*cron.Cron, error) {

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
			ar.logger.Error("Failed to send heartbeat", "error", err, "uuid", staticAgentUUID.String())
		}
	})
	if err != nil {
		ar.logger.Error("Error adding heartbeat schedule", "error", err, "uuid", staticAgentUUID.String())
	}
	return c, nil
}

func (ar *AgentRunner) setupCron(ctx context.Context) (*cron.Cron, error) {
	c := cron.New(cron.WithParser(cron.NewParser(
		cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
	)))
	for pluginName, pluginConfig := range ar.config.Plugins {
		var schedule string
		if pluginConfig.Schedule == nil {
			schedule = "* * * * *"
		} else {
			schedule = *pluginConfig.Schedule
		}

		_, err := c.AddFunc(schedule, func() {
			err := ar.runPlugin(ctx, pluginName, pluginConfig)
			if err != nil {
				// TODO how will we handle these errors ?
				ar.logger.Error("Error running plugin", "error", err)
			}
		})

		if err != nil {
			ar.logger.Error("Error adding plugin schedule", "schedule", schedule, "error", err)
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
	client := sdk.NewClient(http.DefaultClient, &sdk.Config{
		BaseURL: ar.config.ApiConfig.Url,
	})

	defer ar.closePluginClients()

	for pluginName, pluginConfig := range ar.config.Plugins {
		logger := hclog.New(&hclog.LoggerOptions{
			Name:   fmt.Sprintf("runner.%s", pluginName),
			Output: os.Stdout,
			Level:  hclog.Level(ar.config.logVerbosity()),
		})

		labels := map[string]string{
			"_agent":  "concom",
			"_plugin": pluginName,
		}
		for k, v := range pluginConfig.Labels {
			labels[k] = v
		}

		source := ar.pluginLocations[pluginConfig.Source]

		logger.Debug("Running plugin", "source", source)

		if _, err := os.ReadFile(source); err != nil {
			return err
		}

		runnerInstance, err := ar.getRunnerInstance(logger, source)

		if err != nil {
			return err
		}

		config := &proto.Config{}
		err = config.Marshal(pluginConfig.Config)
		if err != nil {
			return err
		}
		_, err = runnerInstance.Configure(&proto.ConfigureRequest{
			Config: config,
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
		resultsHelper := runner.NewApiHelper(logger, client, labels)

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
	}

	return nil
}

// Run the agent as an instance, this is a single run of the agent that will check the
// policies against the plugins.
//
// Returns:
// - error: any error that occurred during the run
func (ar *AgentRunner) runPlugin(ctx context.Context, name string, plugin *agentPlugin) error {
	client := sdk.NewClient(http.DefaultClient, &sdk.Config{
		BaseURL: ar.config.ApiConfig.Url,
	})

	ar.mu.Lock()
	defer ar.mu.Unlock()
	defer ar.closePluginClients()

	policyPaths := make([]string, 0)
	for _, inputBundle := range plugin.Policies {
		policyLocation, err := internal.Download(ctx, string(inputBundle), AgentPolicyDir, "policies", ar.logger)
		if err != nil {
			return err
		}
		policyPaths = append(policyPaths, policyLocation)
	}

	pluginExecutable, err := internal.Download(ctx, plugin.Source, AgentPluginDir, "plugin", ar.logger, remote.WithPlatform(v1.Platform{
		Architecture: runtime.GOARCH,
		OS:           runtime.GOOS,
	}))

	fmt.Println("Running plugin", "source", plugin.Source)
	fmt.Println("Running plugin", "source", pluginExecutable)

	if err != nil {
		return err
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:   fmt.Sprintf("runner.%s", name),
		Output: os.Stdout,
		Level:  hclog.Level(ar.config.logVerbosity()),
	})

	labels := map[string]string{
		"_agent":  "concom",
		"_plugin": name,
	}
	for k, v := range plugin.Labels {
		labels[k] = v
	}

	logger.Debug("Running plugin", "source", pluginExecutable)

	if _, err := os.ReadFile(pluginExecutable); err != nil {
		return err
	}

	runnerInstance, err := ar.getRunnerInstance(logger, pluginExecutable)

	if err != nil {
		return err
	}

	config := &proto.Config{}
	err = config.Marshal(plugin.Config)
	if err != nil {
		return err
	}
	_, err = runnerInstance.Configure(&proto.ConfigureRequest{
		Config: config,
	})
	if err != nil {
		return err
	}

	// Create a new results helper for the plugin to send results back to
	resultsHelper := runner.NewApiHelper(logger, client, labels)

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
	client := sdk.NewClient(http.DefaultClient, &sdk.Config{
		BaseURL: ar.config.ApiConfig.Url,
	})
	heartbeatCtx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()
	heartbeatJson, err := json.Marshal(map[string]interface{}{
		"uuid":    staticAgentUUID,
		"created": time.Now(),
	})
	if err != nil {
		// TODO What to do here ?
		ar.logger.Error("Error marshaling heartbeat", "error", err, "uuid", staticAgentUUID.String())
		return err
	}
	response, err := client.NewRequest(heartbeatCtx, "POST", "/api/heartbeat/", bytes.NewReader(heartbeatJson))
	if err != nil {
		// TODO What to do here ?
		ar.logger.Error("Error sending heartbeat", "error", err, "uuid", staticAgentUUID.String())
		return err
	}
	if response.StatusCode != http.StatusCreated {
		// TODO What to do here ?
		ar.logger.Error("Error heartbeat from server", "code", response.StatusCode, "uuid", staticAgentUUID.String())
		return err
	}
	ar.logger.Info("Successfully heartbeat from server", "uuid", staticAgentUUID.String())
	return nil
}

func (ar *AgentRunner) getRunnerInstance(logger hclog.Logger, path string) (runner.Runner, error) {
	// We're a host! Start by launching the plugin process.
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  runner.HandshakeConfig,
		Plugins:          runner.PluginMap,
		Managed:          true,
		Cmd:              exec.Command(path),
		Logger:           logger,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
	})

	// Connect via RPC
	rpcClient, err := client.Client()
	if err != nil {
		return nil, err
	}

	// Request the plugin
	raw, err := rpcClient.Dispense("runner")
	if err != nil {
		return nil, err
	}

	// We should have a Greeter now! This feels like a normal interface
	// implementation but is in fact over an RPC connection.
	runnerInstance := raw.(runner.Runner)
	return runnerInstance, nil
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
	// Build a set of unique plugin sources
	pluginSources := map[string]struct{}{}

	for _, pluginConfig := range ar.config.Plugins {
		pluginSources[pluginConfig.Source] = struct{}{}
	}

	for source := range pluginSources {
		out, err := internal.Download(ctx, source, AgentPluginDir, "plugin", ar.logger, remote.WithPlatform(v1.Platform{
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
	// Build a set of unique policy sources
	policySources := map[string]struct{}{}

	for _, pluginConfig := range ar.config.Plugins {
		for _, policy := range pluginConfig.Policies {
			policySources[string(policy)] = struct{}{}
		}
	}

	for source := range policySources {
		out, err := internal.Download(ctx, source, AgentPolicyDir, "policies", ar.logger)

		if err != nil {
			return err
		}

		ar.policyLocations[source] = out
	}

	return nil
}

// Checks each item specified and retrieves the source.
// It checks if the source is a path that exists on the filesystem first, if it is then it just
// uses that, if it isn't it will attempt to download the plugin to the filesystem.
//
// We also update the map of plugin sources, this could be an identity map if it's a local
// file or maps from the URL to the local file if we downloaded a remote file.
//
// We return the following:
// * A map of the source to the local file path
// * Errors that occurred during the download process. TODO: What is the right error handling here?
func (ar *AgentRunner) downloadItem(
	type_ string,
	source string,
	outDirPrefix string,
	isArchDependent bool,
) (string, error) {
	location := ""

	ar.logger.Trace("Checking for source", "type", type_, "source", source)

	// First we check if the source is a path that exists on the fs, if so we just use that.
	_, err := os.ReadFile(source)

	if err == nil {
		// The file exists. Just return it.
		ar.logger.Debug("Found source locally, using local file", "type", type_, "File", source)

		// The file exists locally, so we use the local path.
		return source, nil
	}

	// The error we've received is something other than not exists.
	// Exit early with the error
	if !os.IsNotExist(err) {
		return location, err
	}

	if internal.IsOCI(source) {
		ar.logger.Debug("Source looks like an OCI endpoint, attempting to download", "type", type_, "Source", source)
		tag, err := name.NewTag(source)
		if err != nil {
			return location, err
		}

		outDir := path.Join(outDirPrefix, tag.RepositoryStr(), tag.Identifier())

		downloaderImpl, err := oci.NewDownloader(
			tag,
			outDir,
		)
		if err != nil {
			return location, err
		}
		if isArchDependent {
			err = downloaderImpl.Download(remote.WithPlatform(v1.Platform{
				Architecture: runtime.GOARCH,
				OS:           runtime.GOOS,
			}))
		} else {
			err = downloaderImpl.Download()
		}
		if err != nil {
			return location, err
		}

		location := outDir
		if type_ == "plugins" {
			location = path.Join(outDir, "plugin")
		} else if type_ == "policies" {
			location = path.Join(outDir, "policies")
		}

		ar.logger.Debug("Source downloaded successfully", "type", type_, "Destination", outDir)
		// Update the source in the agent configuration to the new path
		return location, nil
	} else {
		ar.logger.Debug("Attempting to download artifact (TODO)", "Source", source)

		return location, errors.New("Downloading artifacts is not yet implemented")
	}
}

func (ar *AgentRunner) closePluginClients() {
	ar.logger.Debug("Cleaning up plugin instances")
	plugin.CleanupClients()
	ar.logger.Debug("Completed plugin cleanup")
}
