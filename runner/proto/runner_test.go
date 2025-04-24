package proto

import (
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"testing"
)

func TestConfig_UnmarshalMap(t *testing.T) {
	t.Run("Basic map", func(t *testing.T) {
		config := &Config{}
		err := config.Marshal(map[string]interface{}{
			"name": "Chris",
			"age":  int32(18),
		})
		assert.NoError(t, err)

		output := map[string]interface{}{}
		err = config.Unmarshal(&output)
		assert.NoError(t, err)
		assert.Equal(t, "Chris", output["name"])
		assert.EqualValues(t, 18, output["age"])
	})
	t.Run("Complex map", func(t *testing.T) {
		config := &Config{}
		err := config.Marshal(map[string]interface{}{
			"name":   "Chris",
			"age":    int32(18),
			"active": false,
			"price":  12.12,
		})
		assert.NoError(t, err)

		output := map[string]interface{}{}
		err = config.Unmarshal(&output)
		assert.NoError(t, err)
		assert.Equal(t, "Chris", output["name"])
		assert.EqualValues(t, 18, output["age"])
		assert.Equal(t, false, output["active"])
		assert.EqualValues(t, 12.12, output["price"])
	})
	t.Run("nest", func(t *testing.T) {
		config := &Config{}
		err := config.Marshal(map[string]interface{}{
			"name": "Chris",
			"friends": map[string]interface{}{
				"chris": map[string]interface{}{
					"age":  18,
					"home": "London",
				},
			},
		})
		assert.NoError(t, err)

		output := map[string]interface{}{}
		err = config.Unmarshal(&output)
		assert.NoError(t, err)
		assert.Equal(t, "Chris", output["name"])
		assert.EqualValues(t, 18, output["friends"].(map[string]interface{})["chris"].(map[string]interface{})["age"])
		assert.EqualValues(t, "London", output["friends"].(map[string]interface{})["chris"].(map[string]interface{})["home"])
	})
	t.Run("list of scalar", func(t *testing.T) {
		config := &Config{}
		err := config.Marshal(map[string]interface{}{
			"name": "Chris",
			"friends": []string{
				"Darren",
				"Rod",
			},
		})
		assert.NoError(t, err)

		output := map[string]interface{}{}
		err = config.Unmarshal(&output)
		assert.NoError(t, err)
		assert.Equal(t, "Chris", output["name"])
		assert.EqualValues(t, []interface{}{
			"Darren",
			"Rod",
		}, output["friends"])
	})
	t.Run("List of map", func(t *testing.T) {
		config := &Config{}
		err := config.Marshal(map[string]interface{}{
			"name": "Chris",
			"friends": []map[string]interface{}{
				{
					"name": "Chris",
				},
			},
		})
		assert.NoError(t, err)

		output := map[string]interface{}{}
		err = config.Unmarshal(&output)
		assert.NoError(t, err)
		assert.Equal(t, "Chris", output["name"])
		assert.Len(t, output["friends"], 1)
		assert.Equal(t, "Chris", output["friends"].([]interface{})[0].(map[string]interface{})["name"])
	})
}

func TestConfigureRequest_KitchenSink(t *testing.T) {
	t.Run("Basic config", func(t *testing.T) {
		yamlContent := `
name: "Chris"
age: 12
`
		input := map[string]interface{}{}
		err := yaml.Unmarshal([]byte(yamlContent), input)
		if err != nil {
			t.Fatal(err)
		}

		config := &Config{}
		err = config.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}

		type PluginConfig struct {
			Name string
			Age  int32
		}
		output := PluginConfig{}
		err = config.Unmarshal(&output)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "Chris", output.Name)
		assert.Equal(t, int32(12), output.Age)
	})
	t.Run("Nested config", func(t *testing.T) {
		yamlContent := `
details:
    name: "Chris"
    age: 20
    active: false
`
		input := map[string]interface{}{}
		err := yaml.Unmarshal([]byte(yamlContent), input)
		if err != nil {
			t.Fatal(err)
		}

		config := &Config{}
		err = config.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}

		type PluginConfig struct {
			Details struct {
				Name   string
				Age    int32
				Active bool
			}
		}
		output := PluginConfig{}
		err = config.Unmarshal(&output)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "Chris", output.Details.Name)
		assert.Equal(t, int32(20), output.Details.Age)
		assert.Equal(t, false, output.Details.Active)
	})
	t.Run("List scalar", func(t *testing.T) {
		yamlContent := `
people:
  - Chris
  - Tanner
`
		input := map[string]interface{}{}
		err := yaml.Unmarshal([]byte(yamlContent), input)
		if err != nil {
			t.Fatal(err)
		}

		config := &Config{}
		err = config.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}

		type PluginConfig struct {
			People []string
		}
		output := PluginConfig{}
		err = config.Unmarshal(&output)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, []string{
			"Chris",
			"Tanner",
		}, output.People)
	})
	t.Run("List Maps", func(t *testing.T) {
		yamlContent := `
people:
  - name: Chris
    age: 20
    active: false
`
		input := map[string]interface{}{}
		err := yaml.Unmarshal([]byte(yamlContent), input)
		if err != nil {
			t.Fatal(err)
		}

		config := &Config{}
		err = config.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}

		type PluginConfig struct {
			People []struct {
				Name   string
				Age    int32
				Active bool
			}
		}
		output := PluginConfig{}
		err = config.Unmarshal(&output)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "Chris", output.People[0].Name)
		assert.Equal(t, int32(20), output.People[0].Age)
		assert.Equal(t, false, output.People[0].Active)
	})
}
