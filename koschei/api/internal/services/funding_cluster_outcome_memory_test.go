package services

import (
	"testing"
	"time"
)

func TestFundingClusterOutcomeMemoryAggregation(t *testing.T) {
	const (
		funderA = "Fund111111111111111111111111111111111111111"
		targetA = "So11111111111111111111111111111111111111112"
		targetB = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	)
	recurrence := FundingRecurrenceAnalysis{
		Available: true, Status: "verified_recurrence", EvidenceStatus: "verified",
		CurrentTarget: "Current11111111111111111111111111111111111", Network: "solana-mainnet",
		Sources: []FundingSourceRecurrence{
			{
				FundingSource: funderA, DistinctTargets: 3, OtherTargets: []string{targetA, targetB},
				ReferencesComplete: true, StoredRowsVerified: true,
			},
		},
	}
	links := fundingClusterOutcomeLinks(recurrence)
	if len(links) != 1 || len(links[funderA]) != 2 {
		t.Fatalf("links=%v", links)
	}
	base := FundingClusterOutcomeMemory{
		Version: FundingClusterOutcomeMemoryVersion, Network: recurrence.Network, CurrentTarget: recurrence.CurrentTarget,
		Status: "no_recurrent_funders", Complete: true, SourceCount: 1,
		Sources: []FundingClusterOutcomeSource{}, Limitations: []string{},
		VerdictAuthority: false, RealWorldIdentityClaim: false, WrongdoingClaim: false, SafetyClaim: false,
	}
	rows := []fundingClusterOutcomeVerdictRow{
		{
			Target: targetA, ModuleID: "liquidity_movement", RiskIndex: 88, RiskLevel: "critical", Grade: "F",
			Verdict: "historical signed liquidity risk", Source: "security_radar",
			ObservedAt: time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			Target: targetA, ModuleID: "holder_concentration", RiskIndex: 22, RiskLevel: "low", Grade: "B",
			Verdict: "historical low finding", Source: "security_radar",
			ObservedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		},
	}
	out := aggregateFundingClusterOutcomeMemory(base, links, rows)
	if out.Status != "material_signed_outcome_history_observed" {
		t.Fatalf("status=%q", out.Status)
	}
	if out.SourceCount != 1 || out.HistoricalTargetCount != 2 || out.SignedHistoryTargetCount != 1 || out.MaterialRiskTargetCount != 1 {
		t.Fatalf("counts source=%d historical=%d signed=%d material=%d", out.SourceCount, out.HistoricalTargetCount, out.SignedHistoryTargetCount, out.MaterialRiskTargetCount)
	}
	if out.VerdictAuthority || out.RealWorldIdentityClaim || out.WrongdoingClaim || out.SafetyClaim {
		t.Fatalf("funding outcome memory must remain context-only: %+v", out)
	}
	if len(out.Sources) != 1 || len(out.Sources[0].Targets) != 2 {
		t.Fatalf("sources=%+v", out.Sources)
	}
	if out.Sources[0].MaterialRiskTargetCount != 1 || out.Sources[0].SignedHistoryTargetCount != 1 {
		t.Fatalf("source counts=%+v", out.Sources[0])
	}
	var material *FundingClusterOutcomeTarget
	for i := range out.Sources[0].Targets {
		if out.Sources[0].Targets[i].Target == targetA {
			material = &out.Sources[0].Targets[i]
		}
	}
	if material == nil || !material.MaterialRiskHistory || material.HighestRiskLevel != "critical" || material.HighestRiskIndex != 88 || material.SignedVerdictCount != 2 {
		t.Fatalf("material target=%+v", material)
	}
	if hash1, hash2 := fundingClusterOutcomeMemoryHash(out), fundingClusterOutcomeMemoryHash(out); hash1 == "" || hash1 != hash2 {
		t.Fatalf("non-deterministic hash: %q %q", hash1, hash2)
	}
}

func TestFundingClusterOutcomeLinksRejectIncompleteReferences(t *testing.T) {
	recurrence := FundingRecurrenceAnalysis{
		Available: true, Status: "reference_gap", CurrentTarget: "current", Network: "solana-mainnet",
		Sources: []FundingSourceRecurrence{
			{FundingSource: "funder", DistinctTargets: 2, OtherTargets: []string{"other"}, ReferencesComplete: false},
		},
	}
	if links := fundingClusterOutcomeLinks(recurrence); len(links) != 0 {
		t.Fatalf("incomplete references must not enter outcome memory: %v", links)
	}
}
