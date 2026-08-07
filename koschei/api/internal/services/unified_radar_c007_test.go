package services

import (
	"testing"
	"time"
)

func TestFundingRecurrenceSingleTargetDoesNotFire(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	report := ApplyCrossTokenFundingRecurrenceRuleV130(UnifiedRadarBehaviorReport{Mint: "current", Signals: []UnifiedRadarSignal{}}, FundingRecurrenceAnalysis{
		Available: true, CurrentTarget: "current", Network: "solana-mainnet",
		Sources: []FundingSourceRecurrence{{FundingSource: "fixture-funder", DistinctTargets: 1, OtherTargets: []string{}, ReferencesComplete: false, StoredRowsVerified: true}},
	}, now)
	signal := report.Signals[len(report.Signals)-1]
	if signal.RuleID != UnifiedRuleCrossTokenFundingRecurrence || signal.Triggered {
		t.Fatalf("signal=%#v", signal)
	}
}

func TestFundingRecurrenceWithholdsWithoutRefs(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	report := ApplyCrossTokenFundingRecurrenceRuleV130(UnifiedRadarBehaviorReport{Mint: "current", Signals: []UnifiedRadarSignal{}}, FundingRecurrenceAnalysis{
		Available: true, CurrentTarget: "current", Network: "solana-mainnet",
		Sources: []FundingSourceRecurrence{{FundingSource: "fixture-funder", DistinctTargets: 2, OtherTargets: []string{}, ReferencesComplete: false, StoredRowsVerified: true}},
	}, now)
	signal := report.Signals[len(report.Signals)-1]
	if signal.Triggered || signal.EvidenceStatus == "verified" || signal.EvidenceStatus == "observed" {
		t.Fatalf("reference-less recurrence became evidence: %#v", signal)
	}
}

func TestFundingRecurrenceVerifiedEntersAcceptanceChainWithoutChangingGrade(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	behavior := ApplyCrossTokenFundingRecurrenceRuleV130(UnifiedRadarBehaviorReport{Mint: "current", Signals: []UnifiedRadarSignal{}}, FundingRecurrenceAnalysis{
		Available: true, CurrentTarget: "current", Network: "solana-mainnet",
		Sources: []FundingSourceRecurrence{{
			FundingSource: "fixture-funder", DistinctTargets: 2, OtherTargets: []string{"other-mint"},
			MemberWallets: []string{"member-a", "member-b"}, ReferencesComplete: true, StoredRowsVerified: true,
		}},
	}, now)
	signal := behavior.Signals[len(behavior.Signals)-1]
	if !signal.Triggered || signal.EvidenceStatus != "verified" {
		t.Fatalf("signal=%#v", signal)
	}
	verdict := EvaluateUnifiedRadarVerdictV130("current", ActorDefenseRuleVerdict{}, behavior)
	found := false
	for _, hit := range verdict.TriggeredRules {
		if hit.RuleID == UnifiedRuleCrossTokenFundingRecurrence {
			found = true
		}
	}
	if !found {
		t.Fatalf("C007 missing from acceptance chain: %#v", verdict.TriggeredRules)
	}
	if verdict.Grade != "-" || verdict.Signed {
		t.Fatalf("evidence-only C007 changed grade/signature: grade=%q signed=%v", verdict.Grade, verdict.Signed)
	}
}
