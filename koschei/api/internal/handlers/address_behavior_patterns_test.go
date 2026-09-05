package handlers

import (
	"testing"
	"time"
)

func TestBuildAddressBehaviorPatternsObservedFamilies(t *testing.T) {
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	relationships := addressRelationshipsReport{
		FlowComplete: true,
		Relationships: []addressRelationship{
			{
				Address: "CounterpartyA", InboundTransfers: 2, OutboundTransfers: 2,
				EvidenceSignatures: []string{"sig-a1", "sig-a2", "sig-a3", "sig-a4"},
			},
		},
	}
	flow := addressFlowReport{FlowComplete: true}
	timeline := addressBehaviorTimelineReport{
		EventCount: 4,
		Events: []addressBehaviorTimelineEvent{
			{ObservedAt: base, EventType: "transfer_in", Signature: "sig-in", Counterparty: "CounterpartyA", VerificationStatus: "verified"},
			{ObservedAt: base.Add(5 * time.Minute), EventType: "transfer_out", Signature: "sig-out", Counterparty: "CounterpartyB", VerificationStatus: "verified"},
			{ObservedAt: base.Add(20 * time.Minute), EventType: "mint_created", Signature: "sig-m1", TokenMint: "MintOne", VerificationStatus: "verified"},
			{ObservedAt: base.Add(30 * time.Minute), EventType: "mint_created", Signature: "sig-m2", TokenMint: "MintTwo", VerificationStatus: "verified"},
		},
	}

	report := buildAddressBehaviorPatterns("WalletA", flow, relationships, timeline)
	if report.TriggeredCount != 4 {
		t.Fatalf("TriggeredCount = %d, want 4", report.TriggeredCount)
	}
	if report.Status != "behavior_patterns_observed" {
		t.Fatalf("Status = %q", report.Status)
	}
	for _, match := range report.Matches {
		if !match.Triggered {
			t.Fatalf("pattern %s was not triggered", match.PatternID)
		}
		if match.GradeEligible || match.VerdictAuthority {
			t.Fatalf("pattern %s unexpectedly has verdict authority", match.PatternID)
		}
	}
}

func TestRapidRedistributionIsTemporalOnlyAndNeedsTwoEvidenceSignatures(t *testing.T) {
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	timeline := addressBehaviorTimelineReport{
		EventCount: 2,
		Events: []addressBehaviorTimelineEvent{
			{ObservedAt: base, EventType: "transfer_in", Signature: "sig-in", Counterparty: "A"},
			{ObservedAt: base.Add(16 * time.Minute), EventType: "transfer_out", Signature: "sig-out", Counterparty: "B"},
		},
	}
	match := addressPatternRapidRedistribution(timeline)
	if match.Triggered {
		t.Fatal("rapid redistribution triggered outside 15 minute window")
	}

	timeline.Events[1].ObservedAt = base.Add(10 * time.Minute)
	match = addressPatternRapidRedistribution(timeline)
	if !match.Triggered {
		t.Fatal("rapid redistribution did not trigger inside 15 minute window")
	}
	if match.EvidenceStatus != "observed" || match.Status != "observed_watch" {
		t.Fatalf("unexpected semantics: status=%q evidence=%q", match.Status, match.EvidenceStatus)
	}
	if match.GradeEligible || match.VerdictAuthority {
		t.Fatal("temporal sequencing must not receive verdict authority")
	}
}

func TestRepeatedMintCreationRequiresDistinctVerifiedMints(t *testing.T) {
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	timeline := addressBehaviorTimelineReport{
		EventCount: 2,
		Events: []addressBehaviorTimelineEvent{
			{ObservedAt: base, EventType: "mint_created", Signature: "sig-1", TokenMint: "SameMint", VerificationStatus: "verified"},
			{ObservedAt: base.Add(time.Minute), EventType: "mint_created", Signature: "sig-2", TokenMint: "SameMint", VerificationStatus: "verified"},
		},
	}
	if match := addressPatternRepeatedMintCreation(timeline); match.Triggered {
		t.Fatal("duplicate evidence for one mint must not count as repeated mint creation")
	}
	timeline.Events[1].TokenMint = "OtherMint"
	if match := addressPatternRepeatedMintCreation(timeline); !match.Triggered {
		t.Fatal("distinct verified mint creation evidence should trigger context pattern")
	}
}
