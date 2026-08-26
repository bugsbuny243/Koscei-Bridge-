package handlers

import "koschei/api/internal/services"

const attackPathProjectionVersion = "koschei-attack-path-projection-v1"

// buildEvidenceBackedAttackPathProjection exposes the already-computed threat
// pathways as an explicit attack-path contract. It does not infer intent or add
// new risk claims; every path preserves the deterministic evidence status,
// evidence keys, required evidence and limitations produced by ThreatAnticipation.
func buildEvidenceBackedAttackPathProjection(threat services.ThreatAnticipationReport) map[string]any {
	paths := append([]services.ThreatPathway{}, threat.Pathways...)
	status := threat.Status
	if len(paths) == 0 {
		status = "insufficient_evidence"
	}
	return map[string]any{
		"version":          attackPathProjectionVersion,
		"status":           status,
		"primary_exposure": threat.PrimaryExposure,
		"paths":            paths,
		"source":           "threat_anticipation.pathways",
		"evidence_policy": map[string]bool{
			"evidence_backed_only":         true,
			"predicts_intent":              false,
			"numeric_probability_disabled": true,
			"unknown_remains_unknown":      true,
		},
	}
}

func attackPathProjectionFromReport(report map[string]any) (map[string]any, bool) {
	if report == nil {
		return nil, false
	}
	threat, ok := report["threat_anticipation"].(services.ThreatAnticipationReport)
	if !ok {
		return nil, false
	}
	return buildEvidenceBackedAttackPathProjection(threat), true
}
