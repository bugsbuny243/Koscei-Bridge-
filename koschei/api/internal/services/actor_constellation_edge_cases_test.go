package services

import (
	"context"
	"testing"
)

func TestBuildActorConstellationNodeCapNeverLeavesDanglingEdge(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (ActorOperationalMemoryReport, error) {
		if wallet != "A" {
			return ActorOperationalMemoryReport{}, nil
		}
		return ActorOperationalMemoryReport{Matches: []ActorOperationalMatch{
			{Wallet: "B", Classification: "verified_counterparty_link", EvidenceStatus: "verified"},
			{Wallet: "C", Classification: "verified_counterparty_link", EvidenceStatus: "verified"},
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
