package internal

type AgentConfig struct {
	PolicyPath string `yaml:"policyPath"`
	PluginPath string `yaml:"pluginPath"`
}

func ReadConfig(configFilePath string) (*AgentConfig, error) {
	if configFilePath == "" {
		return nil, nil
	}

	return nil, nil
}
