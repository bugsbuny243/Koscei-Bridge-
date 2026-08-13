package services

import (
	"context"
	"errors"
	"testing"
)

func TestBuildActorConstellationExpandsStrongEdgesOnly(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (ActorOperationalMemoryReport, error) {
		switch wallet {
		case "A":
			return ActorOperationalMemoryReport{Matches: []ActorOperationalMatch{
				{Wallet: "B", Classification: "verified_counterparty_link", EvidenceStatus: "verified", Rules: []string{"AOM-01"}, DirectVerifiedRelations: 1},
				{Wallet: "X", Classification: "single_operational_overlap", EvidenceStatus: "observed", Rules: []string{"AOM-05"}},
			}}, nil
		case "B":
			return ActorOperationalMemoryReport{Matches: []ActorOperationalMatch{
				{Wallet: "C", Classification: "repeated_operational_overlap", EvidenceStatus: "observed", Rules: []string{"AOM-03"}, SharedCounterpartCount: 2, SharedRelationCount: 2},
			}}, nil
		default:
			return ActorOperationalMemoryReport{}, nil
		}
	}

	report, err := buildActorConstellation(context.Background(), "A", "solana-mainnet", 2, 8, 25, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Available || report.Status != "operational_constellation_observed" {
		t.Fatalf("unexpected report status: %#v", report)
	}
	if report.NodeCount != 3 || report.EdgeCount != 2 {
		t.Fatalf("unexpected graph size: nodes=%d edges=%d", report.NodeCount, report.EdgeCount)
	}
	for _, node := range report.Nodes {
		if node.Wallet == "X" {
			t.Fatal("weak single overlap must not be added to the constellation")
		}
	}
	var c ActorConstellationNode
	for _, node := range report.Nodes {
		if node.Wallet == "C" {
			c = node
		}
	}
	if c.Hop != 2 || c.ViaWallet != "B" {
		t.Fatalf("expected shortest A-B-C path, got %#v", c)
	}
	if report.Policy["same_operator_claim"] != false || report.Policy["transitive_identity_claim"] != false {
		t.Fatalf("identity policy must remain fail-closed: %#v", report.Policy)
	}
}

func TestBuildActorConstellationDoesNotTraverseBeyondDepth(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (ActorOperationalMemoryReport, error) {
		next := map[string]string{"A": "B", "B": "C", "C": "D"}[wallet]
		if next == "" {
			return ActorOperationalMemoryReport{}, nil
		}
		return ActorOperationalMemoryReport{Matches: []ActorOperationalMatch{{
			Wallet: next, Classification: "repeated_funding_overlap", EvidenceStatus: "observed", Rules: []string{"AOM-02"}, SharedFundingSourceCount: 1,
		}}}, nil
	}

	report, err := buildActorConstellation(context.Background(), "A", "solana-mainnet", 2, 8, 25, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if report.NodeCount != 3 {
		t.Fatalf("depth 2 must stop at C, got nodes=%#v", report.Nodes)
	}
	for _, node := range report.Nodes {
		if node.Wallet == "D" {
			t.Fatal("depth cap violated")
		}
	}
}

func TestBuildActorConstellationMarksBoundedViewIncomplete(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (ActorOperationalMemoryReport, error) {
		if wallet != "A" {
			return ActorOperationalMemoryReport{}, nil
		}
		return ActorOperationalMemoryReport{Matches: []ActorOperationalMatch{
			{Wallet: "B", Classification: "verified_counterparty_link", EvidenceStatus: "verified"},
			{Wallet: "C", Classification: "verified_counterparty_link", EvidenceStatus: "verified"},
			{Wallet: "D", Classification: "verified_counterparty_link", EvidenceStatus: "verified"},
		}}, nil
	}

	report, err := buildActorConstellation(context.Background(), "A", "solana-mainnet", 1, 2, 25, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete {
		t.Fatal("fanout truncation must mark the bounded graph incomplete")
	}
	if report.NodeCount != 3 {
		t.Fatalf("fanout=2 should keep seed plus two candidates, got %d", report.NodeCount)
	}
}

func TestBuildActorConstellationDeduplicatesUndirectedEdgesAndKeepsStrongerEvidence(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (ActorOperationalMemoryReport, error) {
		switch wallet {
		case "A":
			return ActorOperationalMemoryReport{Matches: []ActorOperationalMatch{{
				Wallet: "B", Classification: "repeated_funding_overlap", EvidenceStatus: "observed", SharedFundingSourceCount: 1,
			}}}, nil
		case "B":
			return ActorOperationalMemoryReport{Matches: []ActorOperationalMatch{{
				Wallet: "A", Classification: "verified_counterparty_link", EvidenceStatus: "verified", DirectVerifiedRelations: 2,
			}}}, nil
		default:
			return ActorOperationalMemoryReport{}, nil
		}
	}

	report, err := buildActorConstellation(context.Background(), "A", "solana-mainnet", 2, 8, 25, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if report.EdgeCount != 1 {
		t.Fatalf("expected one deduplicated edge, got %#v", report.Edges)
	}
	if report.Edges[0].Classification != "verified_counterparty_link" || report.Edges[0].EvidenceStatus != "verified" {
		t.Fatalf("stronger reverse evidence should replace weaker edge: %#v", report.Edges[0])
	}
}

func TestBuildActorConstellationFailsClosedOnLookupError(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (ActorOperationalMemoryReport, error) {
		if wallet == "B" {
			return ActorOperationalMemoryReport{}, errors.New("database unavailable")
		}
		return ActorOperationalMemoryReport{Matches: []ActorOperationalMatch{{
			Wallet: "B", Classification: "verified_counterparty_link", EvidenceStatus: "verified",
		}}}, nil
	}

	if _, err := buildActorConstellation(context.Background(), "A", "solana-mainnet", 2, 8, 25, lookup); err == nil {
		t.Fatal("lookup failures must not return a partial graph as if it were valid")
	}
}

func TestNormalizeActorConstellationBounds(t *testing.T) {
	depth, fanout, cap := normalizeActorConstellationBounds(99, 99, 99)
	if depth != defaultActorConstellationDepth || fanout != defaultActorConstellationFanout || cap != defaultActorConstellationNodeCap {
		t.Fatalf("unexpected defaults: %d %d %d", depth, fanout, cap)
	}
}
