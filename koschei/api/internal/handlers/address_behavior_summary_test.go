package handlers

import "testing"

func TestBuildAddressBehaviorSummaryHighConfidenceNeedsCompleteVerifiedEvidence(t *testing.T) {
	patterns := newAddressBehaviorPatternsReport("WalletA")
	patterns.Status = "behavior_patterns_observed"
	patterns.TriggeredCount = 2
	patterns.Matches = []addressBehaviorPatternMatch{
		{PatternID: "KOSCH-ADDR-BEH-001", Triggered: true, EvidenceStatus: "verified", Counterparties: []string{"A"}, EvidenceSignatures: []string{"sig-1", "sig-2"}},
		{PatternID: "KOSCH-ADDR-BEH-002", Triggered: true, EvidenceStatus: "verified", Counterparties: []string{"A"}, EvidenceSignatures: []string{"sig-3", "sig-4"}},
	}
	flow := addressFlowReport{FlowComplete: true}
	relationships := addressRelationshipsReport{RelationshipCount: 1}
	timeline := addressBehaviorTimelineReport{EventCount: 4}

	report := buildAddressBehaviorSummary("WalletA", true, flow, relationships, timeline, patterns)
	if report.Status != "observed_behavior_summary_available" {
		t.Fatalf("status = %q", report.Status)
	}
	if report.EvidenceConfidence != "high" {
		t.Fatalf("confidence = %q, want high", report.EvidenceConfidence)
	}
	if len(report.PrimaryObservations) != 2 {
		t.Fatalf("observations = %d, want 2", len(report.PrimaryObservations))
	}
	if report.Policy["risk_verdict"] != false || report.Policy["wrongdoing_claim"] != false {
		t.Fatal("summary unexpectedly received risk authority")
	}
}

func TestBuildAddressBehaviorSummaryBoundedCoverageCannotBeHighConfidence(t *testing.T) {
	patterns := newAddressBehaviorPatternsReport("WalletA")
	patterns.Status = "behavior_patterns_observed"
	patterns.TriggeredCount = 2
	patterns.Matches = []addressBehaviorPatternMatch{
		{PatternID: "KOSCH-ADDR-BEH-001", Triggered: true, EvidenceStatus: "verified", Counterparties: []string{"A"}, EvidenceSignatures: []string{"sig-1", "sig-2"}},
		{PatternID: "KOSCH-ADDR-BEH-002", Triggered: true, EvidenceStatus: "verified", Counterparties: []string{"A"}, EvidenceSignatures: []string{"sig-3", "sig-4"}},
	}
	flow := addressFlowReport{FlowComplete: false}
	relationships := addressRelationshipsReport{RelationshipCount: 1}
	timeline := addressBehaviorTimelineReport{EventCount: 4}

	report := buildAddressBehaviorSummary("WalletA", false, flow, relationships, timeline, patterns)
	if report.EvidenceConfidence == "high" {
		t.Fatal("bounded history/flow must not receive high evidence confidence")
	}
	if len(report.Limitations) < 4 {
		t.Fatalf("limitations = %d, want explicit bounded coverage and policy limitations", len(report.Limitations))
	}
}

func TestBuildAddressBehaviorSummaryObservedWatchIsNotRiskVerdict(t *testing.T) {
	patterns := newAddressBehaviorPatternsReport("WalletA")
	patterns.Status = "behavior_patterns_observed"
	patterns.TriggeredCount = 1
	patterns.Matches = []addressBehaviorPatternMatch{
		{PatternID: "KOSCH-ADDR-BEH-003", Triggered: true, Status: "observed_watch", EvidenceStatus: "observed", EvidenceSignatures: []string{"sig-in", "sig-out"}},
	}
	report := buildAddressBehaviorSummary("WalletA", true, addressFlowReport{FlowComplete: true}, addressRelationshipsReport{}, addressBehaviorTimelineReport{EventCount: 2}, patterns)
	if report.EvidenceConfidence != "medium" {
		t.Fatalf("confidence = %q, want medium", report.EvidenceConfidence)
	}
	if report.Policy["guard_block_authority"] != false {
		t.Fatal("observed watch unexpectedly received Guard block authority")
	}
}
