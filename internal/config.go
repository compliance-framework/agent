package internal

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v2"
)

type configFileType int

const (
	FileTypeYaml configFileType = iota
	FileTypeJson
	FileTypeToml
)

type AgentConfig struct {
	PolicyPath string `yaml:"policyPath" json:"policyPath" toml:"policyPath"`
	PluginPath string `yaml:"pluginPath" json:"pluginPath" toml:"pluginPath"`
}

func ReadConfig(configFilePath string) (*AgentConfig, error) {
	if configFilePath == "" {
		return nil, nil
	}

	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		return nil, err
	}

	readFile, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	if configFilePath[len(configFilePath)-5:] == ".json" {
		return readConfigFromData(readFile, FileTypeJson)
	} else if configFilePath[len(configFilePath)-5:] == ".yaml" || configFilePath[len(configFilePath)-4:] == ".yml" {
		return readConfigFromData(readFile, FileTypeYaml)
	} else if configFilePath[len(configFilePath)-5:] == ".toml" {
		return readConfigFromData(readFile, FileTypeYaml)
	} else {
		return nil, errors.New("Unsupported file type")
	}
}

func readConfigFromData(data []byte, fileType configFileType) (*AgentConfig, error) {
	switch fileType {
	case FileTypeYaml:
		return readYamlConfigFromData(data)
	case FileTypeJson:
		return readJsonConfigFromData(data)
	case FileTypeToml:
		return readTomlConfigFromData(data)
	default:
		return nil, errors.New("Unsupported file type")
	}
}

func readYamlConfigFromData(data []byte) (*AgentConfig, error) {
	var config AgentConfig
	err := yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func readJsonConfigFromData(data []byte) (*AgentConfig, error) {
	var config AgentConfig
	err := json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func readTomlConfigFromData(data []byte) (*AgentConfig, error) {
	var config AgentConfig
	_, err := toml.Decode(string(data), &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
