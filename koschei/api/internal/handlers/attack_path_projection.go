package handlers

import "koschei/api/internal/services"

const attackPathProjectionVersion = "koschei-attack-path-projection-v1"

var attackPathEvidenceRows = map[string][]string{
	"dominant_holder_exit":      {"concentration", "dominant-exit"},
	"mint_inflation":            {"mint"},
	"freeze_abuse":              {"freeze"},
	"liquidity_removal":         {"liquidity", "liq-move"},
	"creator_sell_acceleration": {"creator-sell"},
}

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
	projection := buildEvidenceBackedAttackPathProjection(threat)
	if refs, ok := report["evidence_references"].(map[string]unifiedEvidenceReference); ok {
		if linked := buildAttackPathEvidenceReferences(threat, refs); len(linked) > 0 {
			projection["evidence_references"] = linked
		}
	}
	return projection, true
}

func buildAttackPathEvidenceReferences(threat services.ThreatAnticipationReport, refs map[string]unifiedEvidenceReference) map[string]unifiedEvidenceReference {
	out := map[string]unifiedEvidenceReference{}
	for _, path := range threat.Pathways {
		rows := attackPathEvidenceRows[path.ID]
		if len(rows) == 0 {
			continue
		}
		merged := unifiedEvidenceReference{}
		for _, row := range rows {
			if ref, ok := refs[row]; ok {
				merged = mergeUnifiedEvidenceReferences(merged, ref)
			}
		}
		if attackPathEvidenceReferencePresent(merged, threat.Target) {
			out[path.ID] = merged
		}
	}
	return out
}

func attackPathEvidenceReferencePresent(ref unifiedEvidenceReference, target string) bool {
	if len(ref.Wallets)+len(ref.Signatures)+len(ref.Slots)+len(ref.EvidenceKeys) > 0 {
		return true
	}
	for _, account := range ref.Accounts {
		if account != "" && account != target {
			return true
		}
	}
	return false
}
