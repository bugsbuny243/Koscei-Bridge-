package services

import "testing"

func TestClassifyActorOperationalMatchVerifiedInteractionDoesNotClaimIdentity(t *testing.T) {
	match := classifyActorOperationalMatch(actorOperationalMatchStats{
		Wallet:                  "candidate",
		DirectVerifiedRelations: 1,
	})
	if match.Classification != "verified_counterparty_link" || match.EvidenceStatus != "verified" {
		t.Fatalf("unexpected verified relation classification: %#v", match)
	}
	if len(match.Rules) != 1 || match.Rules[0] != "AOM-01" {
		t.Fatalf("unexpected rules: %#v", match.Rules)
	}
}

func TestClassifyActorOperationalMatchRequiresRepeatedFundingContexts(t *testing.T) {
	weak := classifyActorOperationalMatch(actorOperationalMatchStats{
		Wallet: "candidate", SharedFundingSourceCount: 1, SubjectTokenContexts: 1, CandidateTokenContexts: 2,
	})
	if weak.Classification != "none" {
		t.Fatalf("single subject token context must not become repeated funding overlap: %#v", weak)
	}
	strong := classifyActorOperationalMatch(actorOperationalMatchStats{
		Wallet: "candidate", SharedFundingSourceCount: 1, SubjectTokenContexts: 2, CandidateTokenContexts: 3,
	})
	if strong.Classification != "repeated_funding_overlap" || strong.EvidenceStatus != "observed" {
		t.Fatalf("expected repeated funding overlap: %#v", strong)
	}
}

func TestClassifyActorOperationalMatchPromotesMultiRelationOverlap(t *testing.T) {
	match := classifyActorOperationalMatch(actorOperationalMatchStats{
		Wallet: "candidate", SharedCounterpartCount: 2, SharedRelationCount: 2,
	})
	if match.Classification != "repeated_operational_overlap" || match.EvidenceStatus != "observed" {
		t.Fatalf("expected repeated operational overlap: %#v", match)
	}
	if len(match.Rules) != 1 || match.Rules[0] != "AOM-03" {
		t.Fatalf("unexpected rules: %#v", match.Rules)
	}
}

func TestClassifyActorOperationalMatchObservedDirectLinkIsWatchOnly(t *testing.T) {
	match := classifyActorOperationalMatch(actorOperationalMatchStats{
		Wallet: "candidate", DirectObservedRelations: 2,
	})
	if match.Classification != "observed_counterparty_link" || match.EvidenceStatus != "observed" {
		t.Fatalf("unexpected observed direct relation: %#v", match)
	}
}
