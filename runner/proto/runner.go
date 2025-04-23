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

func processMap(config map[string]interface{}) (*ConfigItemSet, error) {
	set := &ConfigItemSet{}
	for key, v := range config {
		item := &ConfigItem{}
		switch t := v.(type) {
		case string:
			item = &ConfigItem{
				Key:   key,
				Value: &ConfigItem_ValueString{ValueString: t},
			}
		case int:
			item = &ConfigItem{
				Key:   key,
				Value: &ConfigItem_ValueInt{ValueInt: int32(t)},
			}
		case int32:
			item = &ConfigItem{
				Key:   key,
				Value: &ConfigItem_ValueInt{ValueInt: t},
			}
		case int64:
			item = &ConfigItem{
				Key:   key,
				Value: &ConfigItem_ValueInt{ValueInt: int32(t)},
			}
		case float64:
			item = &ConfigItem{
				Key:   key,
				Value: &ConfigItem_ValueInt{ValueInt: int32(t)},
			}
		case []string:
			item = &ConfigItem{
				Key: key,
				Value: &ConfigItem_ValueList{
					ValueList: &ConfigList{Items: t},
				},
			}
		case []interface{}:
			// convert []interface{}→[]string
			strs := make([]string, len(t))
			for i, e := range t {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("list item %d for key %q is not a string: %T", i, key, e)
				}
				strs[i] = s
			}
			item = &ConfigItem{
				Key: key,
				Value: &ConfigItem_ValueList{
					ValueList: &ConfigList{Items: strs},
				},
			}
		case map[string]interface{}:
			recursiveItem, err := processMap(v.(map[string]interface{}))
			if err != nil {
				return nil, err
			}
			item = &ConfigItem{
				Key: key,
				Value: &ConfigItem_ValueConfig{
					ValueConfig: recursiveItem,
				},
			}
		default:
			return nil, fmt.Errorf("unsupported value type %T for key %q", v, key)
		}
		set.Items = append(set.Items, item)
	}
	return set, nil
}

func processValues(output map[string]interface{}, item *ConfigItemSet) {
	for _, i := range item.Items {
		switch v := i.GetValue().(type) {
		default:
			fmt.Printf("unexpected type %T", v)
		case *ConfigItem_ValueConfig:
			recursedOutput := map[string]interface{}{}
			processValues(recursedOutput, i.GetValueConfig())
			output[i.GetKey()] = recursedOutput
		case *ConfigItem_ValueList:
			output[i.GetKey()] = i.GetValueList().GetItems()
		case *ConfigItem_ValueString:
			output[i.GetKey()] = i.GetValueString()
		case *ConfigItem_ValueInt:
			output[i.GetKey()] = i.GetValueInt()
		}
	}
}
