package proto

import (
	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConfigureRequest_ToMap(t *testing.T) {
	t.Run("Basic type", func(t *testing.T) {
		req := &ConfigureRequest{
			Config: &ConfigItemSet{
				Items: []*ConfigItem{
					// Simple type
					{
						Key:   "token",
						Value: &ConfigItem_ValueString{ValueString: "some-token"},
					},
				},
			},
		}

		type Config struct {
			Token string `mapstructure:"token"`
		}
		config := &Config{}
		require.NoError(t, mapstructure.Decode(req.ToMap(), config))
		assert.Equal(t, "some-token", config.Token)
	})
	t.Run("List item", func(t *testing.T) {
		req := &ConfigureRequest{
			Config: &ConfigItemSet{
				Items: []*ConfigItem{
					// Simple type
					{
						Key: "tags",
						Value: &ConfigItem_ValueList{
							ValueList: &ConfigList{
								Items: []string{
									"production",
									"staging",
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
		require.NoError(t, mapstructure.Decode(req.ToMap(), config))
		assert.EqualValues(t, []string{
			"production",
			"staging",
		}, config.Tags)
	})
	t.Run("Nested item", func(t *testing.T) {
		req := &ConfigureRequest{
			Config: &ConfigItemSet{
				Items: []*ConfigItem{
					// Simple type
					{
						Key: "connection",
						Value: &ConfigItem_ValueConfig{
							ValueConfig: &ConfigItemSet{
								Items: []*ConfigItem{
									{
										Key: "url",
										Value: &ConfigItem_ValueConfig{
											ValueConfig: &ConfigItemSet{
												Items: []*ConfigItem{
													{
														Key: "protocol",
														Value: &ConfigItem_ValueString{
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
		}

		type Config struct {
			Connection struct {
				Url struct {
					Protocol string `mapstructure:"protocol"`
				} `mapstructure:"url"`
			} `mapstructure:"connection"`
		}
		config := &Config{}
		require.NoError(t, mapstructure.Decode(req.ToMap(), config))
		assert.EqualValues(t, "http", config.Connection.Url.Protocol)
	})
}

func TestConfigureRequest_FromMap(t *testing.T) {
	t.Run("Basic type", func(t *testing.T) {
		config := map[string]interface{}{
			"token": "some-token",
		}

		req := &ConfigureRequest{}
		err := req.FromMap(config)
		require.NoError(t, err)

		assert.Equal(t, "token", req.GetConfig().GetItems()[0].GetKey())
		assert.Equal(t, "some-token", req.GetConfig().GetItems()[0].GetValueString())
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
		require.NoError(t, err)

		assert.Equal(t, "tags", req.GetConfig().GetItems()[0].GetKey())
		assert.EqualValues(t, []string{
			"production",
			"staging",
		}, req.GetConfig().GetItems()[0].GetValueList().GetItems())
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
		require.NoError(t, err)

		assert.Equal(t, "connection", req.GetConfig().GetItems()[0].GetKey())
		assert.Equal(t, "url", req.GetConfig().GetItems()[0].GetValueConfig().GetItems()[0].GetKey())
		assert.Equal(t, "protocol", req.GetConfig().GetItems()[0].GetValueConfig().GetItems()[0].GetValueConfig().GetItems()[0].GetKey())
		assert.Equal(t, "http", req.GetConfig().GetItems()[0].GetValueConfig().GetItems()[0].GetValueConfig().GetItems()[0].GetValueString())
	})
}
