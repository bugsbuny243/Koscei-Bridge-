package services

import "testing"

func TestFundingArmCarriesCrossTokenRecurrenceLineage(t *testing.T) {
	recurrence := FundingRecurrenceAnalysis{
		Available: true, Status: "verified_recurrence", EvidenceStatus: "verified",
		CurrentTarget: "current-mint", Network: "solana-mainnet",
		Sources: []FundingSourceRecurrence{{
			FundingSource: "funder-wallet", DistinctTargets: 2,
			OtherTargets: []string{"other-mint"}, MemberWallets: []string{"member-a", "member-b"},
			ReferencesComplete: true, StoredRowsVerified: true,
		}},
	}
	arm := buildFundingClusterArm(SecurityRadarRequest{Target: "current-mint", Network: "solana-mainnet"}, radarEvidenceProfile{
		LiveRPC: true, EvidenceStatus: "verified",
		HolderCluster:     HolderClusterAnalysis{Available: true, Confidence: "high", SharedFundingGroupCount: 1, LargestSharedFundingGroup: 2},
		FundingRecurrence: recurrence,
	}, "2026-08-07T12:00:00Z")
	got, ok := arm.Signals["funding_recurrence"].(FundingRecurrenceAnalysis)
	if !ok {
		t.Fatalf("funding recurrence missing from funding arm: %#v", arm.Signals["funding_recurrence"])
	}
	if len(got.Sources) != 1 || got.Sources[0].FundingSource != "funder-wallet" || len(got.Sources[0].OtherTargets) != 1 {
		t.Fatalf("funding recurrence lineage=%#v", got)
	}
}
