package proto

import (
	json "github.com/json-iterator/go"
)

func (c *Config) Marshal(config map[string]interface{}) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	c.Value = data
	return nil
}

func (c *Config) Unmarshal(out any) error {
	return json.Unmarshal(c.GetValue(), out)
}
