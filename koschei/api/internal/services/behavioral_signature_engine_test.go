package services

import "testing"

func TestBehavioralSignatureEngineSeparatesVerifiedAndWatchFamilies(t *testing.T) {
	actorHistory := SecurityIncidentCorpusView{
		Network: "solana-mainnet", ActorWallet: "Actor11111111111111111111111111111111111111",
		Available: true, Complete: true, Status: "verified_incidents_observed",
		Records: []SecurityIncidentCorpusRecord{
			{
				IncidentKey: "KIC1-a", Target: "MintA", ActorWallet: "Actor11111111111111111111111111111111111111",
				EventKind: ActorExitEventLiquidityRemoval, EventSignature: "event-a", EventSlot: 11,
				VerdictSignature: "verdict-a", RiskLevel: "critical", RiskIndex: 91,
			},
			{
				IncidentKey: "KIC1-b", Target: "MintB", ActorWallet: "Actor11111111111111111111111111111111111111",
				EventKind: ActorExitEventLiquidityRemoval, EventSignature: "event-b", EventSlot: 22,
				VerdictSignature: "verdict-b", RiskLevel: "high", RiskIndex: 71,
			},
		},
	}
	funding := FundingClusterOutcomeMemory{
		Network: "solana-mainnet", Complete: true, Status: "material_signed_outcome_history_observed",
		Sources: []FundingClusterOutcomeSource{
			{
				FundingSource: "Funder111", MaterialRiskTargetCount: 2,
				Targets: []FundingClusterOutcomeTarget{
					{Target: "MintA", SignedVerdictCount: 1, MaterialRiskHistory: true},
					{Target: "MintB", SignedVerdictCount: 1, MaterialRiskHistory: true},
				},
			},
		},
	}
	genome := ActorCampaignGenome{
		ActorWallet: actorHistory.ActorWallet, Network: "solana-mainnet", Complete: true,
		Status: "verified_supported", GenomeID: "KCG1-test", PatternHashSHA256: "sha256:test",
	}
	operational := ActorOperationalMemoryReport{
		Wallet: actorHistory.ActorWallet, Network: "solana-mainnet", Available: true,
		Status: "operational_overlap_observed",
		Matches: []ActorOperationalMatch{
			{Wallet: "Rotated111", Classification: "repeated_operational_overlap", EvidenceStatus: "observed", Rules: []string{"AOM-03"}},
		},
	}

	report := BuildBehavioralSignatureReport("MintCurrent", actorHistory, funding, genome, operational)
	if report.Status != "behavior_families_observed" || report.TriggeredCount != 4 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.VerifiedSupportedCount != 2 || report.WatchCount != 2 {
		t.Fatalf("verified=%d watch=%d", report.VerifiedSupportedCount, report.WatchCount)
	}
	if report.Policy["verdict_authority"] != false || report.Policy["grade_authority"] != false || report.Policy["guard_block_authority"] != false {
		t.Fatalf("engine must remain non-authoritative: %+v", report.Policy)
	}

	byID := map[string]BehavioralSignatureMatch{}
	for _, match := range report.Matches {
		byID[match.SignatureID] = match
		if match.GradeEligible || match.VerdictAuthority {
			t.Fatalf("signature acquired authority: %+v", match)
		}
	}
	if byID["KOSCH-BEH-001"].Status != "verified_supported" || byID["KOSCH-BEH-002"].Status != "verified_supported" {
		t.Fatalf("verified signatures=%+v", byID)
	}
	if byID["KOSCH-BEH-003"].Status != "observed_watch" || byID["KOSCH-BEH-004"].Status != "observed_watch" {
		t.Fatalf("watch signatures=%+v", byID)
	}
}

func TestBehavioralSignatureEngineDoesNotMergeDifferentActorsIntoVerifiedRecurrence(t *testing.T) {
	history := SecurityIncidentCorpusView{
		Network: "solana-mainnet", Complete: true, Available: true,
		Records: []SecurityIncidentCorpusRecord{
			{IncidentKey: "KIC1-a", Target: "MintA", ActorWallet: "ActorA", EventKind: "liquidity_removal", EventSignature: "ea", EventSlot: 1, VerdictSignature: "va"},
			{IncidentKey: "KIC1-b", Target: "MintB", ActorWallet: "ActorB", EventKind: "liquidity_removal", EventSignature: "eb", EventSlot: 2, VerdictSignature: "vb"},
		},
	}
	funding := FundingClusterOutcomeMemory{Network: "solana-mainnet", Complete: true, Sources: []FundingClusterOutcomeSource{}}
	report := BuildBehavioralSignatureReport("MintCurrent", history, funding, ActorCampaignGenome{}, ActorOperationalMemoryReport{})
	for _, match := range report.Matches {
		if (match.SignatureID == "KOSCH-BEH-001" || match.SignatureID == "KOSCH-BEH-002") && match.Triggered {
			t.Fatalf("different actors must not become verified recurrence: %+v", match)
		}
	}
}
