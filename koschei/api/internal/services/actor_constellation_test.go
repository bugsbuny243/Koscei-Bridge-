package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testConstellationEvidence(id, status string) []ActorConstellationEvidenceRow {
	return []ActorConstellationEvidenceRow{
		{ID: id + "-1", Signature: "sig-" + id + "-1", Slot: 101, Timestamp: time.Unix(100, 0).UTC(), SourceWallet: "source", DestinationWallet: "destination", Amount: "1", Asset: "SOL", Program: "system", VerificationStatus: status, Relation: "direct_sol_transfer_out"},
		{ID: id + "-2", Signature: "sig-" + id + "-2", Slot: 102, Timestamp: time.Unix(101, 0).UTC(), SourceWallet: "source", DestinationWallet: "destination", Amount: "2", Asset: "SOL", Program: "system", VerificationStatus: status, Relation: "funded_by"},
	}
}

func testConstellationCandidate(match ActorOperationalMatch) actorConstellationCandidate {
	status := match.EvidenceStatus
	if status == "" {
		status = "observed"
	}
	return actorConstellationCandidate{Match: match, Evidence: testConstellationEvidence(match.Wallet, status)}
}

func TestBuildActorConstellationExpandsStrongEdgesOnly(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (actorConstellationLookupResult, error) {
		switch wallet {
		case "A":
			return actorConstellationLookupResult{Complete: true, Candidates: []actorConstellationCandidate{
				testConstellationCandidate(ActorOperationalMatch{Wallet: "B", Classification: "verified_counterparty_link", EvidenceStatus: "verified", Rules: []string{"AOM-01"}, DirectVerifiedRelations: 1}),
				testConstellationCandidate(ActorOperationalMatch{Wallet: "X", Classification: "single_operational_overlap", EvidenceStatus: "observed", Rules: []string{"AOM-05"}}),
			}}, nil
		case "B":
			return actorConstellationLookupResult{Complete: true, Candidates: []actorConstellationCandidate{
				testConstellationCandidate(ActorOperationalMatch{Wallet: "C", Classification: "repeated_operational_overlap", EvidenceStatus: "observed", Rules: []string{"AOM-03"}, SharedCounterpartCount: 2, SharedRelationCount: 2}),
			}}, nil
		default:
			return actorConstellationLookupResult{Complete: true}, nil
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
	if report.Complete {
		t.Fatal("reaching the requested depth frontier must mark the view incomplete")
	}
	for _, node := range report.Nodes {
		if node.Wallet == "X" {
			t.Fatal("weak single overlap must not be added to the constellation")
		}
	}
	for _, edge := range report.Edges {
		if len(edge.Evidence) == 0 {
			t.Fatalf("serious edge must retain evidence rows: %#v", edge)
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
	lookup := func(_ context.Context, wallet, _ string, _ int) (actorConstellationLookupResult, error) {
		next := map[string]string{"A": "B", "B": "C", "C": "D"}[wallet]
		if next == "" {
			return actorConstellationLookupResult{Complete: true}, nil
		}
		return actorConstellationLookupResult{Complete: true, Candidates: []actorConstellationCandidate{
			testConstellationCandidate(ActorOperationalMatch{Wallet: next, Classification: "repeated_funding_overlap", EvidenceStatus: "observed", Rules: []string{"AOM-02"}, SharedFundingSourceCount: 1}),
		}}, nil
	}

	report, err := buildActorConstellation(context.Background(), "A", "solana-mainnet", 2, 8, 25, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if report.NodeCount != 3 {
		t.Fatalf("depth 2 must stop at C, got nodes=%#v", report.Nodes)
	}
	if report.Complete {
		t.Fatal("depth-limited frontier must not claim a complete graph")
	}
	for _, node := range report.Nodes {
		if node.Wallet == "D" {
			t.Fatal("depth cap violated")
		}
	}
}

func TestBuildActorConstellationMarksBoundedViewIncomplete(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (actorConstellationLookupResult, error) {
		if wallet != "A" {
			return actorConstellationLookupResult{Complete: true}, nil
		}
		return actorConstellationLookupResult{Complete: true, Candidates: []actorConstellationCandidate{
			testConstellationCandidate(ActorOperationalMatch{Wallet: "B", Classification: "verified_counterparty_link", EvidenceStatus: "verified"}),
			testConstellationCandidate(ActorOperationalMatch{Wallet: "C", Classification: "verified_counterparty_link", EvidenceStatus: "verified"}),
			testConstellationCandidate(ActorOperationalMatch{Wallet: "D", Classification: "verified_counterparty_link", EvidenceStatus: "verified"}),
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

func TestBuildActorConstellationDeduplicatesUndirectedEdgesAndSynchronizesPathMetadata(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (actorConstellationLookupResult, error) {
		switch wallet {
		case "A":
			return actorConstellationLookupResult{Complete: true, Candidates: []actorConstellationCandidate{
				testConstellationCandidate(ActorOperationalMatch{Wallet: "B", Classification: "repeated_funding_overlap", EvidenceStatus: "observed", Rules: []string{"AOM-02"}, SharedFundingSourceCount: 1}),
			}}, nil
		case "B":
			return actorConstellationLookupResult{Complete: true, Candidates: []actorConstellationCandidate{
				testConstellationCandidate(ActorOperationalMatch{Wallet: "A", Classification: "verified_counterparty_link", EvidenceStatus: "verified", Rules: []string{"AOM-01"}, DirectVerifiedRelations: 2}),
			}}, nil
		default:
			return actorConstellationLookupResult{Complete: true}, nil
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
	for _, node := range report.Nodes {
		if node.Wallet == "B" && (node.LinkClassification != "verified_counterparty_link" || node.EvidenceStatus != "verified") {
			t.Fatalf("path node metadata must follow the final upgraded edge: %#v", node)
		}
	}
}

func TestBuildActorConstellationFailsClosedOnLookupError(t *testing.T) {
	lookup := func(_ context.Context, wallet, _ string, _ int) (actorConstellationLookupResult, error) {
		if wallet == "B" {
			return actorConstellationLookupResult{}, errors.New("database unavailable")
		}
		return actorConstellationLookupResult{Complete: true, Candidates: []actorConstellationCandidate{
			testConstellationCandidate(ActorOperationalMatch{Wallet: "B", Classification: "verified_counterparty_link", EvidenceStatus: "verified", DirectVerifiedRelations: 1}),
		}}, nil
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
