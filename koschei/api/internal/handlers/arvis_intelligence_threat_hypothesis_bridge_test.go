package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestApplyArvisThreatHypothesesRequiresConcreteEvidence(t *testing.T) {
	const target = "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump"
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject(target, "solana-mainnet"),
	}, time.Now().UTC())
	report := map[string]any{
		"threat_anticipation": services.ThreatAnticipationReport{
			Target: target,
			Pathways: []services.ThreatPathway{{
				ID: "mint_inflation", Label: "Mint inflation", Status: "open", EvidenceStatus: "observed",
				Summary: "Mint authority is present.",
			}},
		},
		"evidence_references": map[string]unifiedEvidenceReference{
			"mint": {Accounts: []string{target}},
		},
	}

	applyArvisThreatHypotheses(&investigation, report)
	if len(investigation.Hypotheses) != 0 {
		t.Fatalf("target-only evidence must not create a threat hypothesis: %#v", investigation.Hypotheses)
	}
}

func TestApplyArvisThreatHypothesesProjectsExistingEvidenceLinkedPathway(t *testing.T) {
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
				RequiredEvidence: []string{"LP unlock condition"},
			}},
		},
		"evidence_references": map[string]unifiedEvidenceReference{
			"liquidity": {Accounts: []string{target, "Pool111"}, EvidenceKeys: []string{"pool:Pool111"}},
			"liq-move":  {Signatures: []string{"LiquiditySig111"}, Slots: []int64{321}},
		},
	}

	// Hypotheses intentionally reuse the exact composite evidence created by the
	// existing attack-path bridge rather than inventing a parallel evidence row.
	applyArvisAttackPaths(&investigation, report)
	applyArvisThreatHypotheses(&investigation, report)

	if len(investigation.Hypotheses) != 1 {
		t.Fatalf("expected one evidence-backed hypothesis, got %#v", investigation.Hypotheses)
	}
	hypothesis := investigation.Hypotheses[0]
	if hypothesis.ID != "arvis_hypothesis:liquidity_removal" || hypothesis.Status != "open" {
		t.Fatalf("hypothesis semantics changed: %#v", hypothesis)
	}
	if hypothesis.Classification != "capability_exposure_hypothesis" {
		t.Fatalf("unexpected hypothesis classification: %#v", hypothesis)
	}
	if hypothesis.Confidence != 0 {
		t.Fatalf("hypothesis must not invent numeric probability/confidence: %#v", hypothesis)
	}
	if len(hypothesis.EvidenceRefs) != 1 || hypothesis.EvidenceRefs[0] != "arvis_attack_path:liquidity_removal" {
		t.Fatalf("hypothesis must point to existing ARVIS evidence: %#v", hypothesis)
	}
	if len(hypothesis.RequiredEvidence) != 1 || hypothesis.RequiredEvidence[0] != "LP unlock condition" {
		t.Fatalf("missing evidence requirement was not preserved: %#v", hypothesis)
	}
	if investigation.Decision.Status != services.IntelligenceEvidenceUnverified {
		t.Fatalf("hypothesis projection must not synthesize a customer decision: %#v", investigation.Decision)
	}
}

func TestApplyArvisThreatHypothesesRejectsUntypedThreatData(t *testing.T) {
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet"),
	}, time.Now().UTC())
	applyArvisThreatHypotheses(&investigation, map[string]any{
		"threat_anticipation": map[string]any{"status": "open"},
	})
	if len(investigation.Hypotheses) != 0 {
		t.Fatalf("untyped threat data must not create hypotheses")
	}
}
