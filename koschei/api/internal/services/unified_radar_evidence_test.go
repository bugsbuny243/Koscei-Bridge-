package services

import (
	"testing"
	"time"
)

func TestHardenUnifiedCreatorSellRemainsObserved(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	report := UnifiedRadarBehaviorReport{
		Mint: "MintOne",
		Signals: []UnifiedRadarSignal{{
			RuleID: UnifiedRuleCreatorSellAcceleration, Title: "Creator sell acceleration",
			EvidenceStatus: "verified", Triggered: true, GradeEffect: "compounding_input",
			Summary: "Creator produced 3 verified sells.", Metrics: map[string]any{},
			Signatures: []string{"ledger-signature"}, ObservedAt: now,
		}},
	}
	verification := CreatorSellVerification{
		CandidateSignatures: []string{"ledger-signature"},
		VerifiedSignatures:  []string{"ledger-signature"},
		TransactionsParsed:  1,
	}
	got := HardenUnifiedRadarBehavior(report, verification, HolderClusterAnalysis{})
	if len(got.Signals) != 1 {
		t.Fatalf("signals=%d", len(got.Signals))
	}
	signal := got.Signals[0]
	if signal.EvidenceStatus != "observed" {
		t.Fatalf("creator sell status=%q", signal.EvidenceStatus)
	}
	if len(signal.Signatures) != 1 || signal.Signatures[0] != "ledger-signature" {
		t.Fatalf("verified support signatures=%v", signal.Signatures)
	}
	if len(got.Evidence) != 0 {
		t.Fatalf("ledger-derived acceleration must not create actor evidence rows: %#v", got.Evidence)
	}
}

func TestHardenUnifiedDominantExitRequiresCompleteOutboundEvidenceLine(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	report := UnifiedRadarBehaviorReport{
		Mint: "MintOne",
		Signals: []UnifiedRadarSignal{{
			RuleID: UnifiedRuleDominantHolderFirstExit, Title: "Dominant holder exit",
			EvidenceStatus: "verified", Triggered: true, GradeEffect: "compounding_input",
			Scope: "earliest_verified_exit_in_bounded_window", Summary: "exit",
			Metrics:      map[string]any{"slot": int64(99), "amount": 1000.0},
			EvidenceKeys: []string{"dominant-holder-exit:sig-one"},
			Signatures:   []string{"sig-one"}, ObservedAt: now,
		}},
	}
	cluster := HolderClusterAnalysis{Wallets: []HolderClusterWallet{{
		Rank: 1, Wallet: "HolderOne",
		FlowObservations: []HolderClusterFlowObservation{{
			SourceWallet: "HolderOne", Destination: "PoolOne", Direction: "outbound", Amount: 1000,
			Slot: 99, Signature: "sig-one", ProgramIDs: []string{"DexProgramOne"},
		}},
	}}}
	got := HardenUnifiedRadarBehavior(report, CreatorSellVerification{}, cluster)
	if got.Signals[0].EvidenceStatus != "verified" || !got.Signals[0].Triggered {
		t.Fatalf("exit signal=%#v", got.Signals[0])
	}
	if got.Signals[0].Metrics["direction"] != "outbound" {
		t.Fatalf("direction=%v", got.Signals[0].Metrics["direction"])
	}
	if len(got.Evidence) != 1 {
		t.Fatalf("evidence rows=%d", len(got.Evidence))
	}
	line := BuildActorDefenseEvidenceLine(got.Evidence[0])
	if !line.EvidenceLineComplete {
		t.Fatalf("canonical line gaps=%v", line.EvidenceGaps)
	}
	if line.SourceWallet != "HolderOne" || line.DestinationWallet != "PoolOne" || line.Program != "DexProgramOne" {
		t.Fatalf("canonical line=%#v", line)
	}
}

func TestHardenUnifiedDominantExitRejectsInboundHolderObservation(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	report := UnifiedRadarBehaviorReport{
		Mint: "MintOne",
		Signals: []UnifiedRadarSignal{{
			RuleID: UnifiedRuleDominantHolderFirstExit, Title: "Dominant holder exit",
			EvidenceStatus: "verified", Triggered: true, GradeEffect: "compounding_input",
			Scope: "earliest_verified_exit_in_bounded_window", Summary: "candidate exit",
			Metrics:      map[string]any{"holder_wallet": "HDix", "slot": int64(99), "amount": 0.003123},
			EvidenceKeys: []string{"dominant-holder-exit:inbound-sig"},
			Signatures:   []string{"inbound-sig"}, ObservedAt: now,
		}},
	}
	cluster := HolderClusterAnalysis{Wallets: []HolderClusterWallet{{
		Rank: 1, Wallet: "HDix",
		FlowObservations: []HolderClusterFlowObservation{{
			SourceWallet: "4pta", Destination: "HDix", Direction: "inbound", Kind: "inbound_token_sender_context",
			Amount: 0.003123, Slot: 99, Signature: "inbound-sig", ProgramIDs: []string{"TokenProgram"},
		}},
	}}}
	got := HardenUnifiedRadarBehavior(report, CreatorSellVerification{}, cluster)
	signal := got.Signals[0]
	if signal.Triggered {
		t.Fatalf("inbound holder observation triggered URD-C004: %#v", signal)
	}
	if signal.GradeEffect != "none" || signal.EvidenceStatus != "observed" {
		t.Fatalf("inbound downgrade=%#v", signal)
	}
	if len(signal.Signatures) != 0 || len(signal.EvidenceKeys) != 0 || len(got.Evidence) != 0 {
		t.Fatalf("inbound observation retained grade-changing evidence: signal=%#v evidence=%#v", signal, got.Evidence)
	}
}

func TestHardenUnifiedDominantExitDowngradesIncompleteLine(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	report := UnifiedRadarBehaviorReport{
		Mint: "MintOne",
		Signals: []UnifiedRadarSignal{{
			RuleID: UnifiedRuleDominantHolderFirstExit, EvidenceStatus: "verified", Triggered: true,
			EvidenceKeys: []string{"dominant-holder-exit:sig-one"}, Signatures: []string{"sig-one"},
			Metrics: map[string]any{"slot": int64(99), "amount": 1000.0}, ObservedAt: now,
		}},
	}
	cluster := HolderClusterAnalysis{Wallets: []HolderClusterWallet{{
		Rank: 1, Wallet: "HolderOne",
		FlowObservations: []HolderClusterFlowObservation{{
			SourceWallet: "HolderOne", Destination: "", Direction: "outbound", Amount: 1000,
			Slot: 99, Signature: "sig-one", ProgramIDs: []string{},
		}},
	}}}
	got := HardenUnifiedRadarBehavior(report, CreatorSellVerification{}, cluster)
	if got.Signals[0].Triggered {
		t.Fatalf("incomplete exit remained triggered=%#v", got.Signals[0])
	}
	if len(got.Evidence) != 0 {
		t.Fatalf("incomplete exit produced evidence=%#v", got.Evidence)
	}
}
