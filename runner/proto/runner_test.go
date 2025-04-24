package proto

import (
	"fmt"
	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestConfigureRequest_processScalar(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    interface{}
		wantErr bool
	}{
		{
			name:    "string",
			input:   &Scalar_ValueString{ValueString: "hello"},
			want:    "hello",
			wantErr: false,
		},
		{
			name:    "int",
			input:   &Scalar_ValueInt{ValueInt: 42},
			want:    int64(42), // assuming ValueInt is an int64
			wantErr: false,
		},
		{
			name:    "float",
			input:   &Scalar_ValueFloat{ValueFloat: 3.14},
			want:    float32(3.14),
			wantErr: false,
		},
		{
			name:    "double",
			input:   &Scalar_ValueDouble{ValueDouble: 2.71828},
			want:    float64(2.71828),
			wantErr: false,
		},
		{
			name:    "bool",
			input:   &Scalar_ValueBool{ValueBool: true},
			want:    true,
			wantErr: false,
		},
		{
			name:    "bytes",
			input:   &Scalar_ValueBytes{ValueBytes: []byte{0x01, 0x02, 0x03}},
			want:    []byte{0x01, 0x02, 0x03},
			wantErr: false,
		},
		{
			name:    "unsupported",
			input:   12345, // not a *Scalar_ValueX
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := processScalar("myKey", tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("processScalar(...): error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("processScalar(...) = %v (%T), want %v (%T)",
					got, got, tt.want, tt.want)
			}
			if tt.wantErr {
				// for unsupported, make sure the error wraps the key
				expectedMsg := fmt.Sprintf("unsupported value type %T for key %q", tt.input, "myKey")
				if err.Error() != expectedMsg {
					t.Errorf("error message = %q, want %q", err.Error(), expectedMsg)
				}
			}
		})
	}
}

func TestConfigureRequest_ToMap(t *testing.T) {
	t.Run("Basic type", func(t *testing.T) {
		req := &ConfigureRequest{
			Config: &Config{
				Items: []*ConfigItem{
					// Simple type
					{
						Key: "token",
						Value: &ConfigItem_Scalar{
							Scalar: &Scalar{
								Value: &Scalar_ValueString{
									ValueString: "some-token",
								},
							},
						},
					},
				},
			},
		}

		type Config struct {
			Token string
		}
		config := &Config{}
		_map, err := req.ToMap()
		if err != nil {
			t.Error(err)
		}
		assert.NoError(t, mapstructure.Decode(_map, config))
		assert.Equal(t, "some-token", config.Token)
	})
	t.Run("List item", func(t *testing.T) {
		req := &ConfigureRequest{
			Config: &Config{
				Items: []*ConfigItem{
					// Simple type
					{
						Key: "tags",
						Value: &ConfigItem_ScalarList{
							ScalarList: &ScalarList{
								Items: []*Scalar{
									{
										Value: &Scalar_ValueString{
											"production",
										},
									},
									{
										Value: &Scalar_ValueString{
											"staging",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		type Config struct {
			Tags []string `mapstructure:"tags"`
		}
		config := &Config{}
		_map, err := req.ToMap()
		if err != nil {
			t.Error(err)
		}
		assert.NoError(t, mapstructure.Decode(_map, config))
		assert.EqualValues(t, []string{
			"production",
			"staging",
		}, config.Tags)
	})
	t.Run("Nested item", func(t *testing.T) {
		req := &ConfigureRequest{
			Config: &Config{
				Items: []*ConfigItem{
					// Simple type
					{
						Key: "connection",
						Value: &ConfigItem_Config{
							Config: &Config{
								Items: []*ConfigItem{
									{
										Key: "url",
										Value: &ConfigItem_Config{
											Config: &Config{
												Items: []*ConfigItem{
													{
														Key: "protocol",
														Value: &ConfigItem_Scalar{
															Scalar: &Scalar{
																Value: &Scalar_ValueString{
																	ValueString: "http",
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		type Config struct {
			Connection struct {
				Url struct {
					Protocol string `mapstructure:"protocol"`
				} `mapstructure:"url"`
			} `mapstructure:"connection"`
		}
		config := &Config{}
		_map, err := req.ToMap()
		if err != nil {
			t.Error(err)
		}
		assert.NoError(t, mapstructure.Decode(_map, config))
		assert.EqualValues(t, "http", config.Connection.Url.Protocol)
	})
	t.Run("Object list", func(t *testing.T) {
		req := &ConfigureRequest{
			Config: &Config{
				Items: []*ConfigItem{
					{
						Key: "hosts",
						Value: &ConfigItem_ConfigList{
							ConfigList: &ConfigList{
								Items: []*Config{
									{
										Items: []*ConfigItem{
											{
												Key: "hostname",
												Value: &ConfigItem_Scalar{
													Scalar: &Scalar{
														Value: &Scalar_ValueString{
															ValueString: "worker-1",
														},
													},
												},
											},
											{
												Key: "port",
												Value: &ConfigItem_Scalar{
													Scalar: &Scalar{
														Value: &Scalar_ValueInt{
															ValueInt: 1080,
														},
													},
												},
											},
										},
									},
									{
										Items: []*ConfigItem{
											{
												Key: "hostname",
												Value: &ConfigItem_Scalar{
													Scalar: &Scalar{
														Value: &Scalar_ValueString{
															ValueString: "worker-2",
														},
													},
												},
											},
											{
												Key: "port",
												Value: &ConfigItem_Scalar{
													Scalar: &Scalar{
														Value: &Scalar_ValueInt{
															ValueInt: 720,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		type Config struct {
			Hosts []struct {
				Hostname string
				Port     int32
			}
		}
		config := &Config{}
		_map, err := req.ToMap()
		if err != nil {
			t.Error(err)
		}
		assert.NoError(t, mapstructure.Decode(_map, config))
		// Either of these should be true. We cannot be sure of the order
		assert.Len(t, config.Hosts, 2)

		if config.Hosts[0].Hostname == "worker-1" {
			assert.EqualValues(t, 1080, config.Hosts[0].Port)
			assert.EqualValues(t, "worker-2", config.Hosts[1].Hostname)
			assert.EqualValues(t, 720, config.Hosts[1].Port)
		} else if config.Hosts[0].Hostname == "worker-2" {
			assert.EqualValues(t, 720, config.Hosts[0].Port)
			assert.EqualValues(t, "worker-1", config.Hosts[1].Hostname)
			assert.EqualValues(t, 1080, config.Hosts[1].Port)
		} else {
			assert.Fail(t, "Hosts were mapped incorrectly", "hosts", config.Hosts)
		}
	})
}

func TestConfigureRequest_FromMap(t *testing.T) {
	t.Run("Basic type", func(t *testing.T) {
		config := map[string]interface{}{
			"token": "some-token",
		}

		req := &ConfigureRequest{}
		err := req.FromMap(config)
		assert.NoError(t, err)

		assert.Equal(t, "token", req.GetConfig().GetItems()[0].GetKey())
		assert.Equal(t, "some-token", req.GetConfig().GetItems()[0].GetScalar().GetValueString())
	})
	t.Run("List item", func(t *testing.T) {
		config := map[string]interface{}{
			"tags": []string{
				"production",
				"staging",
			},
		}

		req := &ConfigureRequest{}
		err := req.FromMap(config)
		assert.NoError(t, err)

		assert.Equal(t, "tags", req.GetConfig().GetItems()[0].GetKey())
		for _, item := range req.GetConfig().GetItems()[0].GetScalarList().GetItems() {
			if item.GetValueString() != "production" {
				assert.EqualValues(t, "staging", item.GetValueString())
			} else if item.GetValueString() != "staging" {
				assert.EqualValues(t, "production", item.GetValueString())
			} else {
				assert.Fail(t, "Unexpected key found in scalar list", "item", item.GetValueString())
			}
		}
	})
	t.Run("Nested item", func(t *testing.T) {
		config := map[string]interface{}{
			"connection": map[string]interface{}{
				"url": map[string]interface{}{
					"protocol": "http",
				},
			},
		}

		req := &ConfigureRequest{}
		err := req.FromMap(config)
		assert.NoError(t, err)

		assert.Equal(t, "connection", req.GetConfig().GetItems()[0].GetKey())
		assert.Equal(t, "url", req.GetConfig().GetItems()[0].GetConfig().GetItems()[0].GetKey())
		assert.Equal(t, "protocol", req.GetConfig().GetItems()[0].GetConfig().GetItems()[0].GetConfig().GetItems()[0].GetKey())
		assert.Equal(t, "http", req.GetConfig().GetItems()[0].GetConfig().GetItems()[0].GetConfig().GetItems()[0].GetScalar().GetValueString())
	})
	t.Run("List of configs", func(t *testing.T) {
		config := map[string]interface{}{
			"hosts": []map[string]interface{}{
				{
					"name": "worker-1",
					"port": 1080,
				},
				{
					"name": "worker-2",
					"port": 720,
				},
			},
		}

		req := &ConfigureRequest{}
		err := req.FromMap(config)
		assert.NoError(t, err)
		assert.Equal(t, "hosts", req.GetConfig().GetItems()[0].GetKey())
		assert.Len(t, req.GetConfig().GetItems()[0].GetConfigList().GetItems(), 2)
	})
}

func TestConfigureRequest_Decode(t *testing.T) {
	// Here we do a round trip conversion to ensure it works as it would in a plugin.
	t.Run("Simple", func(t *testing.T) {
		yamlOutput := map[string]interface{}{
			"name":      "foobar",      // simple
			"count":     6,             // int
			"money":     6.12,          // float
			"active":    true,          // bool
			"byteslice": []byte("foo"), // bytes
		}

		processedConfig, err := processMap(yamlOutput)
		assert.NoError(t, err)

		req := ConfigureRequest{Config: processedConfig}

		type PluginConfig struct {
			Name      string
			Count     int64
			Money     float64
			Active    bool
			ByteSlice []byte
		}

		pluginConf := &PluginConfig{}
		err = req.Decode(pluginConf)
		assert.NoError(t, err)

		assert.Equal(t, "foobar", pluginConf.Name)
		assert.Equal(t, int64(6), pluginConf.Count)
		assert.Equal(t, 6.12, pluginConf.Money)
		assert.Equal(t, true, pluginConf.Active)
		assert.Equal(t, []byte("foo"), pluginConf.ByteSlice)
	})
	t.Run("Nested", func(t *testing.T) {
		yamlOutput := map[string]interface{}{
			"experience": map[string]interface{}{
				"cicd": []string{
					"gitlab",
					"github",
				},
				"containers": map[string]interface{}{
					"docker": true,
					"crictl": false,
				},
			},
			"years": []int32{
				2019,
				2020,
			},
		}

		processedConfig, err := processMap(yamlOutput)
		assert.NoError(t, err)

		if processedConfig == nil {
			t.Error("processed config is nil")
		}

		req := ConfigureRequest{Config: processedConfig}

		type PluginConfig struct {
			Experience struct {
				Cicd       []string
				Containers struct {
					Docker bool
					Crictl bool
				}
			}
			Years []int32
		}

		pluginConf := &PluginConfig{}
		err = req.Decode(pluginConf)
		assert.NoError(t, err)
		assert.EqualValues(t, []string{
			"gitlab",
			"github",
		}, pluginConf.Experience.Cicd)

		assert.ObjectsAreEqual(map[string]interface{}{
			"docker": true,
			"crictl": false,
		}, pluginConf.Experience.Containers)

	})

	t.Run("Complex", func(t *testing.T) {
		yamlOutput := map[string]interface{}{
			"host": "http://localhost",
			"port": 2022,
			"connection": map[string]interface{}{
				"url": "http://ssh",
			},
			"hosts": []interface{}{
				"http://one",
				"http://two",
			},
			"people": []map[string]interface{}{
				{
					"name":   "Chris",
					"age":    12,
					"active": true,
				},
				{
					"name":   "George",
					"age":    18,
					"active": false,
				},
			},
		}

		processedConfig, err := processMap(yamlOutput)
		assert.NoError(t, err)

		if processedConfig == nil {
			t.Error("processed config is nil")
			t.FailNow()
		}

		req := ConfigureRequest{Config: processedConfig}

		type PluginConfig struct {
			Host       string
			Port       int32
			Connection struct {
				Url string
			}
			Hosts  []string
			People []struct {
				Name   string
				Age    int32
				Active bool
			}
		}

		pluginConf := &PluginConfig{}
		err = req.Decode(pluginConf)
		assert.NoError(t, err)

		assert.EqualValues(t, []string{
			"http://one",
			"http://two",
		}, pluginConf.Hosts)

		assert.ObjectsAreEqual([]struct {
			Name   string
			Age    int32
			Active bool
		}{
			{
				Name:   "Chris",
				Age:    12,
				Active: true,
			},
			{
				Name:   "George",
				Age:    18,
				Active: false,
			},
		}, pluginConf.People)

	})
}
