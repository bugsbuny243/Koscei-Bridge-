package decision

import "strings"

const Version = "koschei-decision/v1"

type Action string

const (
	ActionAllow    Action = "allow"
	ActionWarn     Action = "warn"
	ActionBlock    Action = "block"
	ActionWithhold Action = "withhold"
)

type Contract struct {
	Version        string `json:"version"`
	Action         Action `json:"action"`
	WithholdReason string `json:"withhold_reason,omitempty"`
	Source         string `json:"source"`
	LegacyValue    string `json:"legacy_value,omitempty"`
}

func NormalizeAction(value string) Action {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(ActionAllow):
		return ActionAllow
	case string(ActionWarn):
		return ActionWarn
	case string(ActionBlock):
		return ActionBlock
	case string(ActionWithhold):
		return ActionWithhold
	default:
		return ActionWithhold
	}
}

func FromTransactionGuard(action, withholdReason string) Contract {
	normalized := NormalizeAction(action)
	reason := ""
	if normalized == ActionWithhold {
		reason = strings.TrimSpace(withholdReason)
		if reason == "" {
			reason = "transaction_guard_evidence_incomplete"
		}
	}
	return Contract{
		Version:        Version,
		Action:         normalized,
		WithholdReason: reason,
		Source:         "solana_transaction_guard",
		LegacyValue:    strings.TrimSpace(action),
	}
}

func FromUnifiedRadar(grade, verdict string) Contract {
	grade = strings.ToUpper(strings.TrimSpace(grade))
	legacy := strings.TrimSpace(verdict)
	contract := Contract{Version: Version, Source: "solana_unified_radar", LegacyValue: grade}
	switch grade {
	case "A", "B":
		contract.Action = ActionAllow
	case "C":
		contract.Action = ActionWarn
	case "D", "E", "F":
		contract.Action = ActionBlock
	default:
		contract.Action = ActionWithhold
		contract.WithholdReason = radarWithholdReason(legacy)
	}
	return contract
}

func radarWithholdReason(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "single_observation":
		return "single_evidence_rule_only"
	case "watch_only":
		return "watch_only_evidence"
	case "evidence_only":
		return "evidence_only_mode"
	case "no_grade_trigger":
		return "no_grade_changing_evidence"
	default:
		return "radar_decision_withheld"
	}
}

func FromExecutionContainment(value string) Contract {
	legacy := strings.ToUpper(strings.TrimSpace(value))
	contract := Contract{Version: Version, Source: "evm_execution_containment_adapter", LegacyValue: legacy}
	switch legacy {
	case "RELEASE":
		contract.Action = ActionAllow
	case "CONTAIN":
		contract.Action = ActionBlock
	case "UNAVAILABLE":
		contract.Action = ActionWithhold
		contract.WithholdReason = "execution_backend_unavailable"
	default:
		contract.Action = ActionWithhold
		contract.WithholdReason = "unknown_execution_containment_decision"
	}
	return contract
}
