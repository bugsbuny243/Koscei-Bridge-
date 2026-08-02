package services

import (
	"testing"
	"time"
)

func TestActorFundingEvidenceUsesInitialOnlyForCompleteHistory(t *testing.T) {
	base := ActorFundingOrigin{
		Wallet:             "Wallet111111111111111111111111111111111111",
		SourceWallet:       "Funder11111111111111111111111111111111111",
		DestinationWallet:  "Wallet111111111111111111111111111111111111",
		AmountSOL:          1,
		Signature:          "funding-signature",
		Slot:               123,
		ObservedAt:         time.Unix(1700000000, 0).UTC(),
		Program:            "system",
		InstructionType:    "transfer",
		VerificationStatus: "verified",
		TrailStatus:        "source_wallet_observed",
		IdentityScope:      "onchain_wallet_only",
	}

	bounded, ok := ActorFundingOriginEvidence(base, "solana-mainnet")
	if !ok {
		t.Fatal("expected bounded funding evidence")
	}
	if bounded.Relation != "oldest_funding_in_window" {
		t.Fatalf("bounded relation=%q", bounded.Relation)
	}
	if bounded.EvidenceKey != "funding-signature:oldest_funding_window" {
		t.Fatalf("bounded evidence key=%q", bounded.EvidenceKey)
	}

	base.HistoryComplete = true
	complete, ok := ActorFundingOriginEvidence(base, "solana-mainnet")
	if !ok {
		t.Fatal("expected complete funding evidence")
	}
	if complete.Relation != "initial_funding_in" {
		t.Fatalf("complete relation=%q", complete.Relation)
	}
	if complete.EvidenceKey != "funding-signature:initial_funding" {
		t.Fatalf("complete evidence key=%q", complete.EvidenceKey)
	}
}
