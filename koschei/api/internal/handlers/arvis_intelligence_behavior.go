package handlers

import (
	"strings"

	"koschei/api/internal/services"
)

// applyArvisBehaviorFindings projects only already-triggered ARVIS behavior
// signals that carry their own concrete evidence keys or transaction
// signatures. It does not evaluate new behavior rules and never upgrades an
// inferred/unverified signal into an observed finding.
func applyArvisBehaviorFindings(investigation *services.IntelligenceInvestigation, behavior services.UnifiedRadarBehaviorReport) {
	if investigation == nil || len(investigation.Subjects) == 0 {
		return
	}
	subject := investigation.Subjects[0]
	if subject.ChainFamily != services.IntelligenceChainFamilySolana {
		return
	}
	if mint := strings.TrimSpace(behavior.Mint); mint != "" && !strings.EqualFold(mint, subject.Raw) {
		return
	}

	for _, signal := range behavior.Signals {
		if !signal.Triggered {
			continue
		}
		status := normalizedBehaviorEvidenceStatus(signal.EvidenceStatus)
		if status == "" {
			continue
		}
		evidenceKeys := uniqueStringsSorted(signal.EvidenceKeys)
		signatures := uniqueStringsSorted(signal.Signatures)
		if len(evidenceKeys) == 0 && len(signatures) == 0 {
			continue
		}

		anchor := ""
		if len(evidenceKeys) > 0 {
			anchor = evidenceKeys[0]
		} else {
			anchor = signatures[0]
		}
		evidenceID := "arvis_behavior:" + strings.TrimSpace(signal.RuleID) + ":" + anchor
		transactionHash := ""
		if len(signatures) == 1 {
			transactionHash = signatures[0]
		}

		investigation.Evidence = append(investigation.Evidence, services.IntelligenceEvidence{
			ID:              evidenceID,
			SubjectID:       subject.ID,
			ChainFamily:     subject.ChainFamily,
			Chain:           subject.Chain,
			Network:         subject.Network,
			Source:          "unified_radar_behavior",
			Status:          status,
			TransactionHash: transactionHash,
			ObservedAt:      signal.ObservedAt.UTC(),
			Address:         strings.TrimSpace(behavior.CreatorWallet),
			Contract:        strings.TrimSpace(behavior.Mint),
			Method:          strings.TrimSpace(signal.RuleID),
			StateChange:     strings.TrimSpace(signal.Summary),
			Provenance:      "existing_arvis_unified_behavior_signal",
			Confidence:      1,
			Attributes: map[string]any{
				"rule_id":         signal.RuleID,
				"title":           signal.Title,
				"grade_effect":    signal.GradeEffect,
				"scope":           signal.Scope,
				"evidence_keys":   evidenceKeys,
				"signatures":      signatures,
				"metrics":         signal.Metrics,
				"thresholds":      signal.Thresholds,
				"limitations":     signal.Limitations,
				"evidence_status": signal.EvidenceStatus,
			},
		})
		investigation.Behaviors = append(investigation.Behaviors, services.IntelligenceBehaviorFinding{
			Kind:         strings.TrimSpace(signal.RuleID),
			Summary:      strings.TrimSpace(signal.Summary),
			Status:       status,
			Confidence:   1,
			EvidenceRefs: []string{evidenceID},
		})
	}
}

func normalizedBehaviorEvidenceStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case services.IntelligenceEvidenceVerified:
		return services.IntelligenceEvidenceVerified
	case services.IntelligenceEvidenceObserved:
		return services.IntelligenceEvidenceObserved
	default:
		return ""
	}
}
