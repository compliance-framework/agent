package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/compliance-framework/agent/runner/proto"

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

type agentPluginConfig map[string]string

type agentPlugin struct {
	Source   string            `mapstructure:"source"`
	Policies []agentPolicy     `mapstructure:"policies"`
	Config   agentPluginConfig `mapstructure:"config"`
	Labels   map[string]string `mapstructure:"labels"`
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
	v.AutomaticEnv()

	loadConfig := func() (*agentConfig, error) {
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

	config, err := loadConfig()
	if err != nil {
		return err
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "agent",
		Output: os.Stdout,
		Level:  hclog.Level(config.logVerbosity()),
	})

	agentRunner := AgentRunner{
		logger:          logger,
		config:          *config,
		pluginLocations: map[string]string{},
		policyLocations: map[string]string{},
	}

	v.OnConfigChange(func(in fsnotify.Event) {
		// We want to wait for any running agent processes to finish first.
		logger.Debug("config file changed", "path", in.Name)
		logger.Debug("waiting for lock to update configurations")
		agentRunner.mu.Lock()
		logger.Debug("received lock to update configurations")
		defer agentRunner.mu.Unlock()

		// When the config changes, if this gives us an error, it's likely due to the config being invalid.
		// This will exit the whole process of the agent. This might not be ideal.
		// Maybe a better strategy here is to re-use the old config and log an error, so the process can continue
		// until the config is fixed ?
		config, err := loadConfig()
		if err != nil {
			logger.Error("Error downloading plugins", "error", err)
			panic(err)
		}

		agentRunner.config = *config

		err = agentRunner.DownloadPlugins()

		if err != nil {
			logger.Error("Error downloading plugins", "error", err)
			panic(err)
		}
		logger.Debug("Successfully reloaded configuration")
	})
	v.WatchConfig()

	err = agentRunner.Run()

	// Don't return the error as that will cause it to spit help out, which is no
	// longer useful at this stage. Log the error and then exit
	if err != nil {
		logger.Error("Error running agent", "error", err)
		os.Exit(1)
	}

	return nil
}

type AgentRunner struct {
	logger hclog.Logger

	mu sync.Mutex

	config agentConfig

	pluginLocations map[string]string
	policyLocations map[string]string

	setupPluginTask   *internal.Task
	setupPoliciesTask *internal.Task

	queryBundles []*rego.Rego
}

func (ar *AgentRunner) Run() error {
	ar.logger.Info("Starting agent", "daemon", ar.config.Daemon)

	err := ar.DownloadPlugins()
	if err != nil {
		return err
	}

	if ar.config.Daemon == true {
		ar.runDaemon()
		return nil
	}

	return ar.runInstance()
}

// Should never return, either handles any error or panics.
// TODO: We should take a cancellable context here, so the caller can cancel the daemon at any time, and continue to whatever is appropriate
func (ar *AgentRunner) runDaemon() {
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		fmt.Println()
		ar.logger.Info("received signal to terminate plugins and exit", "signal", sig)
		ar.closePluginClients()
		os.Exit(0)
	}()

	go daemon.SdNotify(false, "READY=1")

	for {
		err := ar.runInstance()

		if err != nil {
			ar.logger.Error("error running instance", "error", err)
			// No return for now, we keep retrying.
			// TODO: Should we have a retry limit maybe?
		}

		time.Sleep(time.Second * 60)
	}
}

// Run the agent as an instance, this is a single run of the agent that will check the
// policies against the plugins.
//
// Returns:
// - error: any error that occurred during the run
func (ar *AgentRunner) runInstance() error {
	client := sdk.NewClient(http.DefaultClient, &sdk.Config{
		BaseURL: ar.config.ApiConfig.Url,
	})

	ar.mu.Lock()
	defer ar.mu.Unlock()
	defer ar.closePluginClients()

	err := ar.DownloadPolicies()
	if err != nil {
		return err
	}

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
func (ar *AgentRunner) DownloadPlugins() error {
	// Add a task to indicate we've downloaded the items
	task := &internal.Task{
		Title:       "Download plugins",
		Description: "Downloading plugins required to run concom agent",
		SubjectId:   "",
		Activities:  []internal.Activity{},
	}
	defer func() {
		ar.setupPluginTask = task
	}()

	// Build a set of unique plugin sources
	pluginSources := map[string]struct{}{}

	for _, pluginConfig := range ar.config.Plugins {
		pluginSources[pluginConfig.Source] = struct{}{}
	}

	for source := range pluginSources {
		location, activity, err := ar.downloadItem("plugins", source, AgentPluginDir, true)

		if err != nil {
			return err
		}

		task.AddActivity(activity)

		ar.pluginLocations[source] = location
	}

	return nil
}

func (ar *AgentRunner) DownloadPolicies() error {
	// Add a task to indicate we've downloaded the items
	task := &internal.Task{
		Title:       "Download policies",
		Description: "Downloading policies required to run concom agent",
		SubjectId:   "",
		Activities:  []internal.Activity{},
	}
	defer func() {
		ar.setupPoliciesTask = task
	}()

	// Build a set of unique policy sources
	policySources := map[string]struct{}{}

	for _, pluginConfig := range ar.config.Plugins {
		for _, policy := range pluginConfig.Policies {
			policySources[string(policy)] = struct{}{}
		}
	}

	for source := range policySources {
		location, activity, err := ar.downloadItem("policies", source, AgentPolicyDir, false)

		if err != nil {
			return err
		}

		task.AddActivity(activity)

		ar.policyLocations[source] = location
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
) (string, internal.Activity, error) {
	location := ""
	activity := internal.Activity{
		Title:       "Downloading " + type_,
		SubjectId:   "",
		Description: "Downloading " + type_ + " from " + source,
		Type:        type_,
		Steps:       []internal.Step{},
		Tools:       []string{"agent"},
	}

	ar.logger.Trace("Checking for source", "type", type_, "source", source)

	// First we check if the source is a path that exists on the fs, if so we just use that.
	_, err := os.ReadFile(source)

	if err == nil {
		// The file exists. Just return it.
		ar.logger.Debug("Found source locally, using local file", "type", type_, "File", source)

		activity.AddStep(internal.Step{
			Title:       "Plugin found locally",
			SubjectId:   "",
			Description: fmt.Sprintf("Plugin found locally at %s", source),
		})

		// The file exists locally, so we use the local path.
		return source, activity, nil
	}

	// The error we've received is something other than not exists.
	// Exit early with the error
	if !os.IsNotExist(err) {
		activity.AddStep(internal.Step{
			Title:       "Plugin error",
			SubjectId:   "",
			Description: fmt.Sprintf("Error finding plugin on filesystem: '%v'", err),
		})

		return location, activity, err
	}

	if internal.IsOCI(source) {
		ar.logger.Debug("Source looks like an OCI endpoint, attempting to download", "type", type_, "Source", source)
		tag, err := name.NewTag(source)
		if err != nil {
			return location, activity, err
		}

		outDir := path.Join(outDirPrefix, tag.RepositoryStr(), tag.Identifier())

		activity.AddStep(internal.Step{
			Title:       "Plugin OCI endpoint found",
			SubjectId:   "",
			Description: fmt.Sprintf("Plugin found OCI endpoint %s", source),
		})

		downloaderImpl, err := oci.NewDownloader(
			tag,
			outDir,
		)
		if err != nil {
			return location, activity, err
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
			return location, activity, err
		}

		location := outDir
		if type_ == "plugins" {
			location = path.Join(outDir, "plugin")
		} else if type_ == "policies" {
			location = path.Join(outDir, "policies")
		}

		activity.AddStep(internal.Step{
			Title:       "Downloaded Plugin",
			SubjectId:   "",
			Description: fmt.Sprintf("Downloaded plugin to destination %s", location),
		})

		ar.logger.Debug("Source downloaded successfully", "type", type_, "Destination", outDir)
		// Update the source in the agent configuration to the new path
		return location, activity, nil
	} else {
		ar.logger.Debug("Attempting to download artifact (TODO)", "Source", source)

		activity.AddStep(internal.Step{
			Title:       "Plugin error",
			SubjectId:   "",
			Description: "Downloading artifacts is not yet implemented",
		})

		return location, activity, errors.New("Downloading artifacts is not yet implemented")
	}
}

func (ar *AgentRunner) closePluginClients() {
	plugin.CleanupClients()
}
