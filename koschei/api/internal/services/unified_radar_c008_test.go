package services

import (
	"strings"
	"testing"
	"time"
)

func TestCrossTokenExitEventRecurrenceDoesNotFireForSingleTarget(t *testing.T) {
	now := time.Now().UTC()
	recurrence := ActorExitRecurrence{
		Available: true, Status: "single_target_only", EvidenceStatus: "verified",
		ActorWallet: "fixture-wallet", CurrentTarget: "fixture-target-a",
		DistinctTargetsWithEvents: 1, OtherTargets: []string{}, Signatures: []string{"fixture-signature-a"}, Slots: []int64{101},
		ReferencesComplete: false,
	}
	report := ApplyCrossTokenExitEventRecurrenceRuleV140(UnifiedRadarBehaviorReport{Signals: []UnifiedRadarSignal{}}, recurrence, now)
	signal, ok := unifiedRadarSignalByRule(report, UnifiedRuleCrossTokenExitEventRecurrence)
	if !ok {
		t.Fatal("URD-C008 signal missing")
	}
	if signal.Triggered {
		t.Fatal("URD-C008 fired for one target")
	}
}

func TestCrossTokenExitEventRecurrenceWithholdsWithoutRefs(t *testing.T) {
	recurrence := ActorExitRecurrence{
		Available: true, Status: "reference_gap", EvidenceStatus: "unavailable",
		ActorWallet: "fixture-wallet", CurrentTarget: "fixture-target-b",
		DistinctTargetsWithEvents: 2, OtherTargets: []string{"fixture-target-a"},
		Signatures: []string{}, ReferencesComplete: false,
	}
	report := ApplyCrossTokenExitEventRecurrenceRuleV140(UnifiedRadarBehaviorReport{Signals: []UnifiedRadarSignal{}}, recurrence, time.Now().UTC())
	signal, _ := unifiedRadarSignalByRule(report, UnifiedRuleCrossTokenExitEventRecurrence)
	if signal.Triggered || signal.EvidenceStatus == "verified" || signal.EvidenceStatus == "observed" {
		t.Fatalf("reference-gap signal claimed evidence: %#v", signal)
	}
}

func TestCrossTokenExitEventRecurrenceIsEvidenceOnly(t *testing.T) {
	recurrence := ActorExitRecurrence{
		Available: true, Status: "verified_recurrence", EvidenceStatus: "verified",
		ActorWallet: "fixture-wallet", CurrentTarget: "fixture-target-b",
		DistinctTargetsWithEvents: 2, OtherTargets: []string{"fixture-target-a"},
		Signatures: []string{"fixture-signature-a", "fixture-signature-b"}, Slots: []int64{101, 102},
		EventKinds: []string{ActorExitEventLiquidityRemoval}, ReferencesComplete: true,
	}
	behavior := ApplyCrossTokenExitEventRecurrenceRuleV140(UnifiedRadarBehaviorReport{Signals: []UnifiedRadarSignal{}}, recurrence, time.Now().UTC())
	signal, _ := unifiedRadarSignalByRule(behavior, UnifiedRuleCrossTokenExitEventRecurrence)
	if !signal.Triggered || signal.EvidenceStatus != "verified" || signal.GradeEffect != "evidence_only" {
		t.Fatalf("unexpected signal: %#v", signal)
	}
	verdict := EvaluateUnifiedRadarVerdictV140("fixture-target-b", ActorDefenseRuleVerdict{Grade: "-", Verdict: "no_grade_trigger", TriggeredRules: []ActorDefenseRuleHit{}, WatchFlags: []ActorDefenseRuleHit{}}, behavior)
	if verdict.Grade != "-" || verdict.Signed || verdict.Signature != "" {
		t.Fatalf("C008 alone changed verdict: %#v", verdict)
	}
}

func TestCrossTokenExitEventPublicStringsContainNoAccusationTerms(t *testing.T) {
	recurrence := ActorExitRecurrence{
		Available: true, Status: "verified_recurrence", EvidenceStatus: "verified",
		ActorWallet: "fixture-wallet", CurrentTarget: "fixture-target-b",
		DistinctTargetsWithEvents: 2, OtherTargets: []string{"fixture-target-a"},
		Signatures: []string{"fixture-signature-a"}, Slots: []int64{101},
		EventKinds: []string{ActorExitEventLiquidityRemoval}, ReferencesComplete: true,
	}
	behavior := ApplyCrossTokenExitEventRecurrenceRuleV140(UnifiedRadarBehaviorReport{Signals: []UnifiedRadarSignal{}}, recurrence, time.Now().UTC())
	verdict := EvaluateUnifiedRadarVerdictV140("fixture-target-b", ActorDefenseRuleVerdict{Grade: "-", Verdict: "no_grade_trigger"}, behavior)
	values := []string{}
	for _, signal := range behavior.Signals {
		values = append(values, signal.Title, signal.Summary, signal.Scope)
		values = append(values, signal.Limitations...)
	}
	values = append(values, verdict.DecisionPath...)
	for _, value := range values {
		lower := strings.ToLower(value)
		for _, forbidden := range []string{"rug", "scam", "fraud", "criminal"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("public output contains forbidden accusation term %q in %q", forbidden, value)
			}
		}
	}
}
