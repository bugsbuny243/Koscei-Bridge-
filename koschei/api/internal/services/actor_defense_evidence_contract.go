package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ActorDefenseEvidenceLine is the canonical report representation required by
// ACTOR_INVESTIGATION_ENGINE.md section 4. It is derived deterministically from
// the stored relation and metadata; it never upgrades an evidence class.
type ActorDefenseEvidenceLine struct {
	ActorRole                  string         `json:"actor_role"`
	Timestamp                  time.Time      `json:"timestamp"`
	SourceWallet               string         `json:"source_wallet"`
	DestinationWallet          string         `json:"destination_wallet"`
	Program                    string         `json:"program"`
	Amount                     map[string]any `json:"amount"`
	EvidenceLineComplete       bool           `json:"evidence_line_complete"`
	EvidenceGaps               []string       `json:"evidence_gaps,omitempty"`
	PossibleDust               bool           `json:"possible_dust"`
	AddressPoisoningCandidate  bool           `json:"address_poisoning_candidate"`
	GradeEligible              bool           `json:"grade_eligible"`
	EvidenceLabels             []string       `json:"evidence_labels,omitempty"`
	ClassificationReason       string         `json:"classification_reason,omitempty"`
}

// MarshalJSON preserves the existing evidence payload while adding the
// mandatory evidence-line fields. This avoids a second DTO and keeps every API
// consumer on one evidence contract.
func (item ActorDefenseEvidenceRecord) MarshalJSON() ([]byte, error) {
	type alias ActorDefenseEvidenceRecord
	line := BuildActorDefenseEvidenceLine(item)
	return json.Marshal(struct {
		alias
		ActorDefenseEvidenceLine
	}{
		alias:                    alias(item),
		ActorDefenseEvidenceLine: line,
	})
}

func BuildActorDefenseEvidenceLine(item ActorDefenseEvidenceRecord) ActorDefenseEvidenceLine {
	relation := strings.ToLower(strings.TrimSpace(item.Relation))
	role := actorEvidenceMetadataString(item.Metadata, "actor_role")
	if role == "" {
		switch relation {
		case "created_token":
			role = "creator_deployer"
		case "dominant_holder_of":
			role = "dominant_holder"
		case "liquidity_remove_activity":
			role = "liquidity_operator"
		default:
			role = "actor"
		}
	}

	sourceWallet := actorEvidenceMetadataString(item.Metadata, "source_wallet")
	destinationWallet := firstActorEvidenceString(
		actorEvidenceMetadataString(item.Metadata, "destination_wallet"),
		actorEvidenceMetadataString(item.Metadata, "pool_wallet"),
		actorEvidenceMetadataString(item.Metadata, "pool_account"),
	)
	program := actorEvidenceMetadataString(item.Metadata, "program")

	switch relation {
	case "direct_sol_transfer_out", "direct_token_transfer_out":
		sourceWallet = firstActorEvidenceString(sourceWallet, item.ActorWallet)
		destinationWallet = firstActorEvidenceString(destinationWallet, item.CounterpartID)
	case "direct_sol_transfer_in", "direct_token_transfer_in":
		sourceWallet = firstActorEvidenceString(sourceWallet, item.CounterpartID)
		destinationWallet = firstActorEvidenceString(destinationWallet, item.ActorWallet)
	case "liquidity_remove_activity":
		sourceWallet = firstActorEvidenceString(sourceWallet, item.ActorWallet)
	}

	if program == "" {
		switch relation {
		case "direct_sol_transfer_in", "direct_sol_transfer_out":
			program = "system"
		case "direct_token_transfer_in", "direct_token_transfer_out", "dominant_holder_of":
			program = "spl-token"
		case "created_token":
			program = "pump.fun"
		}
	}

	amount := map[string]any{
		"native_sol":   item.AmountNative,
		"token_amount": item.TokenAmount,
		"token_mint":   strings.TrimSpace(item.TokenMint),
	}
	gaps := []string{}
	if strings.TrimSpace(item.Signature) == "" {
		gaps = append(gaps, "signature")
	}
	if item.Slot <= 0 {
		gaps = append(gaps, "slot")
	}
	if item.ObservedAt.IsZero() {
		gaps = append(gaps, "timestamp")
	}
	if sourceWallet == "" {
		gaps = append(gaps, "source_wallet")
	}
	if destinationWallet == "" {
		gaps = append(gaps, "destination_wallet")
	}
	if program == "" {
		gaps = append(gaps, "program")
	}
	if strings.TrimSpace(item.VerificationStatus) == "" {
		gaps = append(gaps, "verification_status")
	}

	classification := ClassifyActorDefenseEvidence(item)
	return ActorDefenseEvidenceLine{
		ActorRole:                 role,
		Timestamp:                 item.ObservedAt,
		SourceWallet:              sourceWallet,
		DestinationWallet:         destinationWallet,
		Program:                   program,
		Amount:                    amount,
		EvidenceLineComplete:      len(gaps) == 0,
		EvidenceGaps:              gaps,
		PossibleDust:              classification.PossibleDust,
		AddressPoisoningCandidate: classification.AddressPoisoningCandidate,
		GradeEligible:             classification.GradeEligible,
		EvidenceLabels:            classification.Labels,
		ClassificationReason:      classification.Reason,
	}
}

func actorEvidenceMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, exists := metadata[key]
	if !exists || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func firstActorEvidenceString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}
