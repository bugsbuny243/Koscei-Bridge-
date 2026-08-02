package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestBuildActorSecurityIntelligenceBuildsVerifiedLinks(t *testing.T) {
	target := "TokenMint111111111111111111111111111111"
	creator := "Creator1111111111111111111111111111111"
	holderWallet := "Holder11111111111111111111111111111111"
	funder := "Funder11111111111111111111111111111111"

	source := map[string]any{
		"creator_wallet":            creator,
		"creator_relation_verified": true,
		"source":                    "pumpportal",
		"signature":                 "LaunchSig111",
	}
	creatorIntel := map[string]any{
		"creator_wallet":              creator,
		"recent_signatures_seen":      40,
		"recent_transactions_checked": 8,
		"previous_launch_count":       2,
		"creator_is_top_holder":       true,
		"creator_holder_percentage":   4.2,
		"observed_launches":           []map[string]any{{"target": target, "signature": "LaunchSig111", "source": "pumpportal"}},
		"funding_wallets":             []map[string]any{{"wallet": funder, "amount": 12.5, "transactions": 1}},
		"recipient_wallets":           []map[string]any{{"wallet": holderWallet, "amount": 1000.0, "transactions": 1, "matches_top_holder": true, "holder_rank": 2, "holder_percentage": 4.2}},
	}
	holder := services.HolderIntelligence{Rows: []services.HolderIntelligenceRow{{
		Rank: 2, OwnerWallet: holderWallet, OwnerResolved: true, Role: "externally_owned_wallet",
		RoleConfidence: "high", RiskBearing: true, Balance: 1000, RawPercentage: 4.2,
		CirculatingPercentage: 4.2, Evidence: []string{"Owner wallet resolved from parsed token account."},
	}}}
	cluster := services.HolderClusterAnalysis{
		WalletsRequested: 3, WalletsAnalyzed: 3,
		Wallets: []services.HolderClusterWallet{{
			Rank: 2, Wallet: holderWallet, HolderPercentage: 4.2,
			SignaturesObserved: 20, ParsedTransactions: 3,
			FundingSource: funder, FundingAmountSOL: 12.5,
		}},
		Flow: services.HolderClusterFlowAnalysis{Available: true, Observations: []services.HolderClusterFlowObservation{{
			SourceWallet: holderWallet, Destination: "Exit111111111111111111111111111111111",
			Kind: "external_token_recipient", Amount: 500, Slot: 123, Signature: "FlowSig111",
			Evidence: []string{"Target-token balance decreased and recipient increased in the same transaction."},
		}}},
	}

	got := buildActorSecurityIntelligence(target, source, creatorIntel, holder, cluster)
	if got["status"] != "verified_linked_actor_network" {
		t.Fatalf("unexpected status: %v", got["status"])
	}
	if got["confidence"] != "high" {
		t.Fatalf("unexpected confidence: %v", got["confidence"])
	}
	if creatorIntelInt(got["creator_linked_top_holder_count"]) != 1 {
		t.Fatalf("expected one creator-holder link, got %v", got["creator_linked_top_holder_count"])
	}
	links, ok := got["links"].([]map[string]any)
	if !ok || len(links) < 4 {
		t.Fatalf("expected evidence links, got %#v", got["links"])
	}
}

func TestBuildActorSecurityIntelligenceDoesNotInventActor(t *testing.T) {
	got := buildActorSecurityIntelligence("Mint111", map[string]any{}, map[string]any{}, services.HolderIntelligence{}, services.HolderClusterAnalysis{})
	if got["available"] != false {
		t.Fatalf("actor intelligence must remain unavailable without evidence: %#v", got)
	}
	if got["status"] != "actor_evidence_unavailable" {
		t.Fatalf("unexpected status: %v", got["status"])
	}
	if got["confidence"] != "none" {
		t.Fatalf("unexpected confidence: %v", got["confidence"])
	}
}
