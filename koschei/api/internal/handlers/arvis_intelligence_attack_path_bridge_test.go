package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestApplyArvisAttackPathsRequiresConcreteEvidenceReference(t *testing.T) {
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet"),
	}, time.Now().UTC())
	report := map[string]any{
		"threat_anticipation": services.ThreatAnticipationReport{
			Target: "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump",
			Pathways: []services.ThreatPathway{{
				ID: "mint_inflation", Label: "Mint inflation", Status: "unknown", EvidenceStatus: "unverified",
			}},
		},
		"evidence_references": map[string]unifiedEvidenceReference{
			"mint": {Accounts: []string{"62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump"}},
		},
	}

	applyArvisAttackPaths(&investigation, report)
	if len(investigation.AttackPaths) != 0 {
		t.Fatalf("target-only evidence must not create an intelligence attack path: %#v", investigation.AttackPaths)
	}
}

func TestApplyArvisAttackPathsProjectsExistingLinkedPathway(t *testing.T) {
	const target = "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump"
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject(target, "solana-mainnet"),
	}, time.Now().UTC())
	report := map[string]any{
		"threat_anticipation": services.ThreatAnticipationReport{
			Target: target,
			Pathways: []services.ThreatPathway{{
				ID: "liquidity_removal", Label: "Liquidity removal", Status: "open", Capacity: "high",
				EvidenceStatus: "observed", Summary: "Liquidity control remains technically available.",
				RequiredEvidence: []string{"LP ownership proof"}, Limitations: []string{"unlock condition unresolved"},
			}},
		},
		"evidence_references": map[string]unifiedEvidenceReference{
			"liquidity": {Accounts: []string{target, "Pool111"}, EvidenceKeys: []string{"pool:Pool111"}},
			"liq-move":  {Signatures: []string{"LiquiditySig111"}, Slots: []int64{321}},
		},
	}

	applyArvisAttackPaths(&investigation, report)
	if len(investigation.AttackPaths) != 1 {
		t.Fatalf("expected one intelligence attack path, got %#v", investigation.AttackPaths)
	}
	path := investigation.AttackPaths[0]
	if path.ID != "arvis_path:liquidity_removal" || path.Status != "open" {
		t.Fatalf("pathway semantics changed: %#v", path)
	}
	if path.Confidence != 0 {
		t.Fatalf("attack path must not invent numeric probability/confidence: %#v", path)
	}
	if len(path.EvidenceRefs) != 1 {
		t.Fatalf("expected evidence-linked path: %#v", path)
	}
	if len(investigation.Evidence) != 1 {
		t.Fatalf("expected one composite evidence reference, got %#v", investigation.Evidence)
	}
	evidence := investigation.Evidence[0]
	if evidence.Provenance != "existing_arvis_attack_path_evidence_reference" || evidence.Status != services.IntelligenceEvidenceObserved {
		t.Fatalf("unexpected evidence projection: %#v", evidence)
	}
	if evidence.TransactionHash != "LiquiditySig111" || evidence.BlockOrSlot != 321 {
		t.Fatalf("single concrete transaction reference should be preserved: %#v", evidence)
	}
	if investigation.Decision.Status != services.IntelligenceEvidenceUnverified {
		t.Fatalf("attack path projection must not synthesize a customer decision: %#v", investigation.Decision)
	}
}

func TestApplyArvisAttackPathsRejectsUntypedThreatData(t *testing.T) {
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet"),
	}, time.Now().UTC())
	applyArvisAttackPaths(&investigation, map[string]any{
		"threat_anticipation": map[string]any{"status": "open"},
	})
	if len(investigation.AttackPaths) != 0 || len(investigation.Evidence) != 0 {
		t.Fatalf("untyped threat data must not create intelligence attack paths")
	}
}
