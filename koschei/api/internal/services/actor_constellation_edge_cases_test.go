package services

import (
	"context"
	"testing"
)

func TestBuildActorConstellationNodeCapNeverLeavesDanglingEdge(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (actorConstellationLookupResult, error) {
		if wallet != "A" {
			return actorConstellationLookupResult{Complete: true}, nil
		}
		return actorConstellationLookupResult{Complete: true, Candidates: []actorConstellationCandidate{
			testConstellationCandidate(ActorOperationalMatch{Wallet: "B", Classification: "verified_counterparty_link", EvidenceStatus: "verified", DirectVerifiedRelations: 1}),
			testConstellationCandidate(ActorOperationalMatch{Wallet: "C", Classification: "verified_counterparty_link", EvidenceStatus: "verified", DirectVerifiedRelations: 1}),
		}}, nil
	}

	report, err := buildActorConstellation(context.Background(), "A", "solana-mainnet", 1, 8, 2, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete {
		t.Fatal("node-cap truncation must mark the view incomplete")
	}
	if report.NodeCount != 2 || report.EdgeCount != 1 {
		t.Fatalf("node cap must not leave an edge to an omitted node: nodes=%#v edges=%#v", report.Nodes, report.Edges)
	}
	nodes := map[string]bool{}
	for _, node := range report.Nodes {
		nodes[node.Wallet] = true
	}
	for _, edge := range report.Edges {
		if !nodes[edge.FromWallet] || !nodes[edge.ToWallet] {
			t.Fatalf("dangling edge detected: %#v", edge)
		}
	}
}

func TestActorConstellationVerifiedEdgeAlwaysOutranksObservedCounters(t *testing.T) {
	verified := ActorConstellationEdge{Classification: "verified_counterparty_link", DirectVerifiedRelations: 1}
	observed := ActorConstellationEdge{Classification: "repeated_operational_overlap", VerifiedOverlapCount: 2_000_000}
	funding := ActorConstellationEdge{Classification: "repeated_funding_overlap", SharedFundingSourceCount: 2_000_000}
	if actorConstellationEdgeRank(verified) <= actorConstellationEdgeRank(observed) {
		t.Fatalf("verified direct evidence must outrank observed operational counters: verified=%d observed=%d", actorConstellationEdgeRank(verified), actorConstellationEdgeRank(observed))
	}
	if actorConstellationEdgeRank(observed) <= actorConstellationEdgeRank(funding) {
		t.Fatalf("repeated operational overlap must outrank repeated funding overlap: observed=%d funding=%d", actorConstellationEdgeRank(observed), actorConstellationEdgeRank(funding))
	}
}

func TestActorConstellationEvidenceSupportRejectsIncompleteSeriousClaim(t *testing.T) {
	rows := testConstellationEvidence("broken", "verified")
	rows[0].Signature = ""
	rows = rows[:1]
	if actorConstellationEvidenceSupports("verified_counterparty_link", rows) {
		t.Fatal("verified edge must not be supported by an incomplete serious evidence row")
	}
}
