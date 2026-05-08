package internal

const AgentConfigHashLabel = "_agent_config_hash"
const EvidenceUUIDSeedLabel = "_evidence_uuid"

func IsReservedEvidenceLabel(key string) bool {
	switch key {
	case "_agent", "_plugin", AgentConfigHashLabel, EvidenceUUIDSeedLabel:
		return true
	default:
		return false
	}
}
