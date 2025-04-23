package proto

import "C"
import (
	"fmt"
	"github.com/go-viper/mapstructure/v2"
)

func (c *ConfigureRequest) ToMap() map[string]interface{} {
	config := map[string]interface{}{}
	processValues(config, c.GetConfig())
	return config
}

func (c *ConfigureRequest) FromMap(config map[string]interface{}) error {
	set, err := processMap(config)
	if err != nil {
		panic(err)
	}
	*c = ConfigureRequest{
		Config: set,
	}
	return nil
}

func (c *ConfigureRequest) Decode(config any) error {
	return mapstructure.Decode(c.ToMap(), config)
}

func processScalar(key string, item interface{}) (interface{}, error) {
	switch t := item.(type) {
	case *Scalar_ValueString:
		return t.ValueString, nil
	case *Scalar_ValueInt:
		return t.ValueInt, nil
	case *Scalar_ValueFloat:
		return t.ValueFloat, nil
	case *Scalar_ValueBool:
		return t.ValueBool, nil
	case *Scalar_ValueDouble:
		return t.ValueDouble, nil
	case *Scalar_ValueBytes:
		return t.ValueBytes, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T for key %q", item, key)
	}
}

func processConfigItem(key string, item interface{}) (*ConfigItem, error) {
	switch t := item.(type) {
	case string:
		return &ConfigItem{
			Key:   key,
			Value: &ConfigItem_Scalar{Scalar: &Scalar{Value: &Scalar_ValueString{ValueString: t}}},
		}, nil
	case int:
		return &ConfigItem{
			Key:   key,
			Value: &ConfigItem_Scalar{Scalar: &Scalar{Value: &Scalar_ValueInt{ValueInt: int64(t)}}},
		}, nil
	case int32:
		return &ConfigItem{
			Key:   key,
			Value: &ConfigItem_Scalar{Scalar: &Scalar{Value: &Scalar_ValueInt{ValueInt: int64(t)}}},
		}, nil
	case int64:
		return &ConfigItem{
			Key:   key,
			Value: &ConfigItem_Scalar{Scalar: &Scalar{Value: &Scalar_ValueInt{ValueInt: t}}},
		}, nil
	case float64:
		return &ConfigItem{
			Key:   key,
			Value: &ConfigItem_Scalar{Scalar: &Scalar{Value: &Scalar_ValueDouble{ValueDouble: t}}},
		}, nil
	case float32:
		return &ConfigItem{
			Key:   key,
			Value: &ConfigItem_Scalar{Scalar: &Scalar{Value: &Scalar_ValueFloat{ValueFloat: t}}},
		}, nil
	case []string:
		items := []*Scalar{}
		for _, j := range t {
			processed, err := processConfigItem(key, j)
			if err != nil {
				return nil, err
			}
			if processed != nil {
				items = append(items, processed.GetScalar())
			}
		}
		return &ConfigItem{
			Key: key,
			Value: &ConfigItem_ScalarList{
				ScalarList: &ScalarList{Items: items},
			},
		}, nil
	case map[string]interface{}:
		config, err := processMap(t)
		if err != nil {
			return nil, err
		}
		return &ConfigItem{
			Key: key,
			Value: &ConfigItem_Config{
				Config: config,
			},
		}, nil
	case []map[string]interface{}:
		items := []*Config{}
		for _, j := range t {
			config, err := processMap(j)
			if err != nil {
				return nil, err
			}
			items = append(items, config)
		}
		return &ConfigItem{
			Key: key,
			Value: &ConfigItem_ConfigList{
				ConfigList: &ConfigList{Items: items},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T for key %q", item, key)
	}
}

func processMap(config map[string]interface{}) (*Config, error) {
	set := &Config{}
	for key, v := range config {
		item, err := processConfigItem(key, v)
		if err != nil {
			return nil, err
		}
		if item != nil {
			set.Items = append(set.Items, item)
		}
	}
	return set, nil
}

func processValues(output map[string]interface{}, item *Config) error {
	for _, i := range item.Items {
		switch v := i.GetValue().(type) {
		default:
			fmt.Printf("unexpected type %T", v)
		case *ConfigItem_Config:
			recursedOutput := map[string]interface{}{}
			err := processValues(recursedOutput, i.GetConfig())
			if err != nil {
				return err
			}
			output[i.GetKey()] = recursedOutput
		case *ConfigItem_ConfigList:
			list := []interface{}{}
			for _, config := range i.GetConfigList().GetItems() {
				recursedOutput := map[string]interface{}{}
				err := processValues(recursedOutput, config)
				if err != nil {
					return err
				}
				list = append(list, recursedOutput)
			}
			output[i.GetKey()] = list
		case *ConfigItem_Scalar:
			j, err := processScalar(i.GetKey(), i.GetScalar().GetValue())
			if err != nil {
				return err
			}
			output[i.GetKey()] = j
		case *ConfigItem_ScalarList:
			list := []interface{}{}
			for _, scalar := range i.GetScalarList().GetItems() {
				j, err := processScalar(i.GetKey(), scalar.GetValue())
				if err != nil {
					return err
				}
				list = append(list, j)
			}
			output[i.GetKey()] = list
		}
	}
	return nil
}
