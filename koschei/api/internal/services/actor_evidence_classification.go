package services

import (
	"sort"
	"strings"
)

const ActorPossibleDustNativeSOLMax = 0.00001

type ActorDefenseEvidenceClassification struct {
	PossibleDust              bool     `json:"possible_dust"`
	AddressPoisoningCandidate bool     `json:"address_poisoning_candidate"`
	GradeEligible             bool     `json:"grade_eligible"`
	Labels                    []string `json:"evidence_labels,omitempty"`
	Reason                    string   `json:"classification_reason,omitempty"`
}

// ClassifyActorDefenseEvidence keeps micro-transfer observations visible while
// preventing them from silently becoming creator/funder relationship proof.
// The threshold is intentionally narrow and matches the live 0.000001–0.00001
// SOL history-noise pattern observed in the reference actor dossier.
func ClassifyActorDefenseEvidence(item ActorDefenseEvidenceRecord) ActorDefenseEvidenceClassification {
	classification := ActorDefenseEvidenceClassification{GradeEligible: true}
	relation := strings.ToLower(strings.TrimSpace(item.Relation))
	if relation != "direct_sol_transfer_in" && relation != "direct_sol_transfer_out" {
		return classification
	}
	if item.AmountNative <= 0 || item.AmountNative > ActorPossibleDustNativeSOLMax {
		return classification
	}

	classification.PossibleDust = true
	classification.GradeEligible = false
	classification.Labels = append(classification.Labels, "possible_dust")
	classification.Reason = "Micro SOL transfer retained as possible dust and excluded from grade-changing direct-transfer rules."

	if relation == "direct_sol_transfer_in" && !actorEvidenceClassificationMetadataBool(item.Metadata, "actor_signed") {
		classification.AddressPoisoningCandidate = true
		classification.Labels = append(classification.Labels, "address_poisoning_candidate")
		classification.Reason = "Unsigned inbound micro SOL transfer retained as a possible dust/address-poisoning candidate; it is not funding or relationship proof."
	}
	sort.Strings(classification.Labels)
	return classification
}

func actorEvidenceClassificationMetadataBool(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	value, ok := metadata[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}
