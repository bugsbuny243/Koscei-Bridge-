package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestAttackPathProjectionPreservesEvidenceBackedThreatPathways(t *testing.T) {
	threat := services.ThreatAnticipationReport{
		Status:          "evidence_backed_pathway_analysis",
		PrimaryExposure: "Liquidity removal remains technically available.",
		Pathways: []services.ThreatPathway{
			{
				ID: "liquidity_removal", Label: "Liquidity removal", Status: "open",
				Capacity: "high", EvidenceStatus: "observed",
				EvidenceKeys: []string{"liquidity_movement"},
			},
		},
	}

	projection := buildEvidenceBackedAttackPathProjection(threat)
	if projection["version"] != attackPathProjectionVersion {
		t.Fatalf("unexpected version: %v", projection["version"])
	}
	paths, ok := projection["paths"].([]services.ThreatPathway)
	if !ok || len(paths) != 1 {
		t.Fatalf("expected one preserved threat pathway, got %#v", projection["paths"])
	}
	if paths[0].ID != "liquidity_removal" || paths[0].EvidenceStatus != "observed" {
		t.Fatalf("pathway evidence was not preserved: %#v", paths[0])
	}
	policy, ok := projection["evidence_policy"].(map[string]bool)
	if !ok || !policy["evidence_backed_only"] || policy["predicts_intent"] {
		t.Fatalf("attack-path evidence policy is unsafe: %#v", projection["evidence_policy"])
	}
}

func TestTechnicalProjectionAddsAttackPathOnlyFromTypedThreatEvidence(t *testing.T) {
	report := map[string]any{
		"target": "mint-1",
		"threat_anticipation": services.ThreatAnticipationReport{
			Status:   "insufficient_evidence",
			Pathways: []services.ThreatPathway{{ID: "mint_inflation", Status: "unknown", EvidenceStatus: "unverified"}},
		},
	}
	projected := unifiedInvestigationTechnicalProjection(report)
	if _, ok := projected["attack_path"]; !ok {
		t.Fatal("technical projection did not expose attack_path")
	}

	untyped := unifiedInvestigationTechnicalProjection(map[string]any{"target": "mint-2", "threat_anticipation": map[string]any{"status": "fake"}})
	if _, ok := untyped["attack_path"]; ok {
		t.Fatal("attack_path must not be fabricated from untyped/untrusted data")
	}
}
