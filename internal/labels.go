package internal

const AgentConfigHashLabel = "_agent_config_hash"

func IsReservedEvidenceLabel(key string) bool {
	switch key {
	case "_agent", "_plugin", AgentConfigHashLabel:
		return true
	default:
		return false
	}
}
