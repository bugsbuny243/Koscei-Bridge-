package handlers

import (
	"strings"

	"koschei/api/internal/services"
)

// applyArvisThreatHypotheses projects only existing typed ThreatAnticipation
// pathways that already have concrete linked evidence. It does not create a new
// risk score, predict intent, or upgrade evidence status. ARVIS remains the
// authoritative evidence engine; the chain-neutral contract only gives the
// existing pathway analysis a stable hypothesis shape for future multi-chain
// consumers.
func applyArvisThreatHypotheses(investigation *services.IntelligenceInvestigation, report map[string]any) {
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
		pathID := strings.TrimSpace(pathway.ID)
		if pathID == "" {
			continue
		}
		ref, exists := linked[pathID]
		if !exists || !attackPathEvidenceReferencePresent(ref, threat.Target) {
			continue
		}

		evidenceID := "arvis_attack_path:" + pathID
		if !intelligenceEvidenceIDPresent(investigation.Evidence, evidenceID) {
			continue
		}

		title := strings.TrimSpace(pathway.Label)
		if title == "" {
			title = pathID
		}
		investigation.Hypotheses = append(investigation.Hypotheses, services.IntelligenceThreatHypothesis{
			ID:               "arvis_hypothesis:" + pathID,
			Title:            title,
			Classification:   "capability_exposure_hypothesis",
			Status:           strings.TrimSpace(pathway.Status),
			Basis:            strings.TrimSpace(pathway.Summary),
			EvidenceRefs:     []string{evidenceID},
			RequiredEvidence: append([]string{}, pathway.RequiredEvidence...),
			Confidence:       0,
		})
	}
}

func attachArvisIntelligenceThreatHypotheses(assembly *unifiedInvestigationAssembly) {
	if assembly == nil || assembly.Report == nil {
		return
	}
	investigation, ok := assembly.Report["intelligence_contract"].(services.IntelligenceInvestigation)
	if !ok {
		return
	}
	applyArvisThreatHypotheses(&investigation, assembly.Report)
	assembly.Report["intelligence_contract"] = investigation
}

func intelligenceEvidenceIDPresent(evidence []services.IntelligenceEvidence, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	for _, item := range evidence {
		if strings.TrimSpace(item.ID) == id {
			return true
		}
	}
	return false
}
