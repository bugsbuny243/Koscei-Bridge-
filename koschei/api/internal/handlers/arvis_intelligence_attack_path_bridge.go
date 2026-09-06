package handlers

import (
	"strings"

	"koschei/api/internal/services"
)

func applyArvisAttackPaths(investigation *services.IntelligenceInvestigation, report map[string]any) {
	if investigation == nil || len(investigation.Subjects) == 0 || report == nil {
		return
	}
	root := investigation.Subjects[0]
	if root.ChainFamily != services.IntelligenceChainFamilySolana {
		return
	}

	threat, ok := report["threat_anticipation"].(services.ThreatAnticipationReport)
	if !ok {
		return
	}
	projection, ok := attackPathProjectionFromReport(report)
	if !ok {
		return
	}
	linked, ok := projection["evidence_references"].(map[string]unifiedEvidenceReference)
	if !ok || len(linked) == 0 {
		return
	}

	for _, pathway := range threat.Pathways {
		ref, exists := linked[pathway.ID]
		if !exists || !attackPathEvidenceReferencePresent(ref, threat.Target) {
			continue
		}

		evidenceID := "arvis_attack_path:" + strings.TrimSpace(pathway.ID)
		status := intelligenceStatusFromThreatEvidence(pathway.EvidenceStatus)
		evidence := services.IntelligenceEvidence{
			ID:          evidenceID,
			SubjectID:   root.ID,
			ChainFamily: root.ChainFamily,
			Chain:       root.Chain,
			Network:     root.Network,
			Source:      "threat_anticipation.pathways",
			Status:      status,
			Method:      strings.TrimSpace(pathway.ID),
			Provenance:  "existing_arvis_attack_path_evidence_reference",
			Confidence:  1,
			Attributes: map[string]any{
				"pathway_status":    pathway.Status,
				"capacity":          pathway.Capacity,
				"evidence_status":   pathway.EvidenceStatus,
				"wallets":           append([]string{}, ref.Wallets...),
				"accounts":          append([]string{}, ref.Accounts...),
				"signatures":        append([]string{}, ref.Signatures...),
				"slots":             append([]int64{}, ref.Slots...),
				"evidence_keys":     append([]string{}, ref.EvidenceKeys...),
				"required_evidence": append([]string{}, pathway.RequiredEvidence...),
				"limitations":       append([]string{}, pathway.Limitations...),
			},
		}
		if len(ref.Signatures) == 1 {
			evidence.TransactionHash = strings.TrimSpace(ref.Signatures[0])
		}
		if len(ref.Slots) == 1 {
			evidence.BlockOrSlot = ref.Slots[0]
		}
		investigation.Evidence = append(investigation.Evidence, evidence)

		title := strings.TrimSpace(pathway.Label)
		if title == "" {
			title = strings.TrimSpace(pathway.ID)
		}
		investigation.AttackPaths = append(investigation.AttackPaths, services.IntelligenceAttackPath{
			ID:           "arvis_path:" + strings.TrimSpace(pathway.ID),
			Title:        title,
			Status:       strings.TrimSpace(pathway.Status),
			Impact:       strings.TrimSpace(pathway.Summary),
			Confidence:   0,
			EvidenceRefs: []string{evidenceID},
		})
	}
}

func intelligenceStatusFromThreatEvidence(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case services.IntelligenceEvidenceVerified:
		return services.IntelligenceEvidenceVerified
	case services.IntelligenceEvidenceObserved:
		return services.IntelligenceEvidenceObserved
	case services.IntelligenceEvidenceInferred:
		return services.IntelligenceEvidenceInferred
	default:
		return services.IntelligenceEvidenceUnverified
	}
}
