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
				EvidenceKeys:     []string{"liquidity_movement"},
				RequiredEvidence: []string{"LP mint and LP token owner"},
				Limitations:      []string{"unlock conditions remain unresolved"},
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
	if len(paths[0].RequiredEvidence) != 1 || paths[0].RequiredEvidence[0] != "LP mint and LP token owner" {
		t.Fatalf("required evidence was not preserved: %#v", paths[0].RequiredEvidence)
	}
	if len(paths[0].Limitations) != 1 || paths[0].Limitations[0] != "unlock conditions remain unresolved" {
		t.Fatalf("pathway limitations were not preserved: %#v", paths[0].Limitations)
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

func TestAttackPathProjectionLinksConcreteEvidenceReferences(t *testing.T) {
	threat := services.ThreatAnticipationReport{
		Target: "Mint111",
		Status: "evidence_backed_pathway_analysis",
		Pathways: []services.ThreatPathway{
			{ID: "liquidity_removal", Status: "open", EvidenceStatus: "observed"},
			{ID: "creator_sell_acceleration", Status: "observed", EvidenceStatus: "observed"},
			{ID: "coordinated_holder_exit", Status: "watch", EvidenceStatus: "observed"},
		},
	}
	report := map[string]any{
		"threat_anticipation": threat,
		"evidence_references": map[string]unifiedEvidenceReference{
			"liquidity": {
				Accounts:     []string{"Mint111", "Pool111", "LPMint111"},
				Slots:        []int64{200},
				EvidenceKeys: []string{"pool:Pool111@200"},
			},
			"liq-move": {
				Signatures: []string{"LiquiditySig111"},
				Slots:      []int64{201},
			},
			"creator-sell": {
				Wallets:      []string{"Creator111"},
				Signatures:   []string{"CreatorSellSig111"},
				Slots:        []int64{300},
				EvidenceKeys: []string{"creator-sell:CreatorSellSig111"},
			},
		},
	}

	projection, ok := attackPathProjectionFromReport(report)
	if !ok {
		t.Fatal("expected typed attack path projection")
	}
	linked, ok := projection["evidence_references"].(map[string]unifiedEvidenceReference)
	if !ok {
		t.Fatalf("expected attack-path evidence links, got %#v", projection["evidence_references"])
	}
	liquidity := linked["liquidity_removal"]
	assertContainsString(t, liquidity.Accounts, "Pool111")
	assertContainsString(t, liquidity.Signatures, "LiquiditySig111")
	assertContainsInt64(t, liquidity.Slots, 200)
	assertContainsInt64(t, liquidity.Slots, 201)
	creator := linked["creator_sell_acceleration"]
	assertContainsString(t, creator.Wallets, "Creator111")
	assertContainsString(t, creator.Signatures, "CreatorSellSig111")
	if _, exists := linked["coordinated_holder_exit"]; exists {
		t.Fatal("coordinated holder exit must not be linked until a direct evidence-row contract exists")
	}
}

func TestAttackPathProjectionDoesNotPromoteTargetOnlyReferenceToEvidence(t *testing.T) {
	threat := services.ThreatAnticipationReport{
		Target:   "MintOnly",
		Pathways: []services.ThreatPathway{{ID: "mint_inflation", Status: "unknown", EvidenceStatus: "unverified"}},
	}
	report := map[string]any{
		"threat_anticipation": threat,
		"evidence_references": map[string]unifiedEvidenceReference{
			"mint": {Accounts: []string{"MintOnly"}},
		},
	}

	projection, ok := attackPathProjectionFromReport(report)
	if !ok {
		t.Fatal("expected typed attack path projection")
	}
	if _, exists := projection["evidence_references"]; exists {
		t.Fatalf("target-only reference must not be promoted to attack-path evidence: %#v", projection["evidence_references"])
	}
}
