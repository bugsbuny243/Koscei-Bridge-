package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestArvisBehaviorFindingsProjectsVerifiedTriggeredSignalWithEvidenceKey(t *testing.T) {
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet"),
	}, time.Unix(100, 0).UTC())
	behavior := services.UnifiedRadarBehaviorReport{
		Mint:          "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump",
		CreatorWallet: "Creator1111111111111111111111111111111111",
		Signals: []services.UnifiedRadarSignal{{
			RuleID:         services.UnifiedRuleCreatorSellAcceleration,
			Title:          "Creator sell acceleration",
			EvidenceStatus: services.IntelligenceEvidenceVerified,
			Triggered:      true,
			Summary:        "Creator sell acceleration is transaction-backed.",
			EvidenceKeys:   []string{"creator-sell:Sig111"},
			Signatures:     []string{"Sig111"},
			ObservedAt:     time.Unix(200, 0).UTC(),
		}},
	}

	applyArvisBehaviorFindings(&investigation, behavior)

	if len(investigation.Behaviors) != 1 || len(investigation.Evidence) != 1 {
		t.Fatalf("expected one behavior and one evidence row, got behaviors=%d evidence=%d", len(investigation.Behaviors), len(investigation.Evidence))
	}
	finding := investigation.Behaviors[0]
	evidence := investigation.Evidence[0]
	if finding.Status != services.IntelligenceEvidenceVerified || evidence.Status != services.IntelligenceEvidenceVerified {
		t.Fatalf("verified status was not preserved: finding=%q evidence=%q", finding.Status, evidence.Status)
	}
	if len(finding.EvidenceRefs) != 1 || finding.EvidenceRefs[0] != evidence.ID {
		t.Fatalf("behavior evidence ref does not point to emitted evidence: %#v vs %q", finding.EvidenceRefs, evidence.ID)
	}
	if evidence.Provenance != "existing_arvis_unified_behavior_signal" {
		t.Fatalf("unexpected provenance: %q", evidence.Provenance)
	}
	if evidence.TransactionHash != "Sig111" {
		t.Fatalf("single concrete signature was not preserved: %q", evidence.TransactionHash)
	}
	if investigation.Decision.Status != services.IntelligenceEvidenceUnverified || investigation.Decision.Action != "investigate" || investigation.Decision.Confidence != 0 {
		t.Fatalf("behavior projection must not synthesize a customer decision: %#v", investigation.Decision)
	}
}

func TestArvisBehaviorFindingsProjectsObservedSignalWithSignature(t *testing.T) {
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet"),
	}, time.Now().UTC())
	behavior := services.UnifiedRadarBehaviorReport{
		Mint: "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump",
		Signals: []services.UnifiedRadarSignal{{
			RuleID:         services.UnifiedRuleDominantHolderFirstExit,
			EvidenceStatus: services.IntelligenceEvidenceObserved,
			Triggered:      true,
			Summary:        "Dominant-holder exit observed.",
			Signatures:     []string{"ExitSig111"},
		}},
	}

	applyArvisBehaviorFindings(&investigation, behavior)
	if len(investigation.Behaviors) != 1 || investigation.Behaviors[0].Status != services.IntelligenceEvidenceObserved {
		t.Fatalf("expected one observed behavior, got %#v", investigation.Behaviors)
	}
	if len(investigation.Evidence) != 1 || investigation.Evidence[0].TransactionHash != "ExitSig111" {
		t.Fatalf("expected observed signature evidence, got %#v", investigation.Evidence)
	}
}

func TestArvisBehaviorFindingsWithholdsInferredUnverifiedAndEvidenceFreeSignals(t *testing.T) {
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet"),
	}, time.Now().UTC())
	behavior := services.UnifiedRadarBehaviorReport{
		Mint: "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump",
		Signals: []services.UnifiedRadarSignal{
			{RuleID: "inferred", EvidenceStatus: services.IntelligenceEvidenceInferred, Triggered: true, EvidenceKeys: []string{"inferred:key"}},
			{RuleID: "unverified", EvidenceStatus: services.IntelligenceEvidenceUnverified, Triggered: true, Signatures: []string{"UnverifiedSig"}},
			{RuleID: "evidence-free", EvidenceStatus: services.IntelligenceEvidenceVerified, Triggered: true},
			{RuleID: "not-triggered", EvidenceStatus: services.IntelligenceEvidenceVerified, Triggered: false, EvidenceKeys: []string{"verified:key"}},
		},
	}

	applyArvisBehaviorFindings(&investigation, behavior)
	if len(investigation.Behaviors) != 0 || len(investigation.Evidence) != 0 {
		t.Fatalf("unsafe behavior signals leaked into intelligence: behaviors=%#v evidence=%#v", investigation.Behaviors, investigation.Evidence)
	}
}

func TestArvisBehaviorFindingsRejectsMismatchedMintAndEVMSubject(t *testing.T) {
	solana := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet"),
	}, time.Now().UTC())
	signal := services.UnifiedRadarSignal{
		RuleID:         services.UnifiedRuleCreatorSellAcceleration,
		EvidenceStatus: services.IntelligenceEvidenceVerified,
		Triggered:      true,
		EvidenceKeys:   []string{"creator-sell:Sig222"},
	}
	applyArvisBehaviorFindings(&solana, services.UnifiedRadarBehaviorReport{Mint: "DifferentMint11111111111111111111111111111111", Signals: []services.UnifiedRadarSignal{signal}})
	if len(solana.Behaviors) != 0 {
		t.Fatalf("mismatched mint must not project behavior: %#v", solana.Behaviors)
	}

	evm := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("0xe1e5f00a9b0255ca4df85b3130ee0f77d15acc2d", "ethereum-mainnet"),
	}, time.Now().UTC())
	applyArvisBehaviorFindings(&evm, services.UnifiedRadarBehaviorReport{Signals: []services.UnifiedRadarSignal{signal}})
	if len(evm.Behaviors) != 0 || len(evm.Evidence) != 0 {
		t.Fatalf("Solana behavior must not leak into EVM intelligence: behaviors=%#v evidence=%#v", evm.Behaviors, evm.Evidence)
	}
}
