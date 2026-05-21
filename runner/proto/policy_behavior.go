package proto

import (
	"slices"
	"strings"
)

func (r *EvalRequest) WithDefaultPolicyBehavior(defaults map[string][]string) *EvalRequest {
	if r == nil {
		return nil
	}

	return &EvalRequest{
		PolicyPaths:    slices.Clone(r.PolicyPaths),
		ApiServer:      r.ApiServer,
		PolicyBehavior: mergePolicyBehavior(defaults, r.PolicyBehavior),
	}
}

func (r *EvalRequest) WithUndefinedMappedTo(behavior []string) *EvalRequest {
	if r == nil {
		return nil
	}

	copy := &EvalRequest{
		PolicyPaths:    slices.Clone(r.PolicyPaths),
		ApiServer:      r.ApiServer,
		PolicyBehavior: mergePolicyBehavior(nil, r.PolicyBehavior),
	}

	for _, path := range copy.PolicyPaths {
		if pathCoveredByPolicyBehavior(path, copy.PolicyBehavior) {
			continue
		}
		if copy.PolicyBehavior == nil {
			copy.PolicyBehavior = make(map[string]*StringList)
		}
		copy.PolicyBehavior[path] = &StringList{Values: slices.Clone(behavior)}
	}

	return copy
}

func (r *EvalRequest) PolicyPathsForBehavior(behavior string) []string {
	if r == nil {
		return nil
	}

	if len(r.PolicyBehavior) == 0 {
		return []string{}
	}

	matchingKeys := make([]string, 0, len(r.PolicyBehavior))
	for key, list := range r.PolicyBehavior {
		if list == nil || !slices.Contains(list.Values, behavior) {
			continue
		}
		matchingKeys = append(matchingKeys, key)
	}

	if len(matchingKeys) == 0 {
		return []string{}
	}

	filtered := make([]string, 0, len(r.PolicyPaths))
outer:
	for _, path := range r.PolicyPaths {
		for _, key := range matchingKeys {
			if pathCoveredByPolicyBehavior(path, map[string]*StringList{key: nil}) {
				filtered = append(filtered, path)
				continue outer
			}
		}
	}

	return filtered
}

func mergePolicyBehavior(defaults map[string][]string, configured map[string]*StringList) map[string]*StringList {
	if len(defaults) == 0 && len(configured) == 0 {
		return nil
	}

	merged := make(map[string]*StringList, len(defaults)+len(configured))
	for key, values := range defaults {
		merged[key] = &StringList{Values: slices.Clone(values)}
	}

	for key, list := range configured {
		if list == nil {
			merged[key] = nil
			continue
		}
		merged[key] = &StringList{Values: slices.Clone(list.Values)}
	}

	return merged
}

func pathCoveredByPolicyBehavior(path string, behavior map[string]*StringList) bool {
	for key := range behavior {
		if strings.Contains(path, key) {
			return true
		}
	}

	return false
}
