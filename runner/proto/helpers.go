package proto

import "google.golang.org/protobuf/types/known/structpb"

// PolicyBehaviorMappingFromStruct converts a protobuf Struct to map[string][]string
// This is used to convert policy_behavior_mapping from proto to Go format
func PolicyBehaviorMappingFromStruct(s *structpb.Struct) map[string][]string {
	if s == nil {
		return nil
	}
	result := make(map[string][]string)
	for k, v := range s.AsMap() {
		if slice, ok := v.([]interface{}); ok {
			strSlice := make([]string, 0, len(slice))
			for _, item := range slice {
				if str, ok := item.(string); ok {
					strSlice = append(strSlice, str)
				}
			}
			result[k] = strSlice
		}
	}
	return result
}

// GetFilteredPolicyPaths returns policy paths filtered by the specified behavior
// This method uses the policy_behavior_mapping from the EvalRequest to filter
func (r *EvalRequest) GetFilteredPolicyPaths(behavior string) []string {
	mapping := PolicyBehaviorMappingFromStruct(r.GetPolicyBehaviorMapping())
	if len(mapping) == 0 {
		if behavior != "" {
			return []string{}
		}
		return r.GetPolicyPaths()
	}

	filtered := make([]string, 0, len(r.GetPolicyPaths()))
	for _, path := range r.GetPolicyPaths() {
		if mappedBehaviors, exists := mapping[path]; exists {
			for _, mappedBehavior := range mappedBehaviors {
				if mappedBehavior == behavior {
					filtered = append(filtered, path)
					break
				}
			}
		}
	}
	return filtered
}
