package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestLiquidityMovementActorEvidenceCreatorRemovalIsStrictVerifiedEvidence(t *testing.T) {
	lp := services.LPControlEvidence{
		TokenMint:    "TokenMint111",
		PoolAddress:  "Pool111",
		PoolProgram:  "Program111",
		CreatorWallet: "Creator111",
		ObservedAt:   time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
	}
	movement := services.LiquidityMovementEvidence{
		Kind:               "remove_liquidity",
		Signature:          "Sig111",
		Slot:               12345,
		BlockTime:          "2026-08-10T11:59:00Z",
		ActorWallet:        "Creator111",
		PoolAddress:        "Pool111",
		Program:            "Program111",
		SourceWallet:       "Pool111",
		DestinationWallet:  "Creator111",
		TokenDelta:         -150,
		QuoteDelta:         -4.5,
		CreatorRelated:     true,
		CreatorRelation:    "verified_investigated_creator_signer",
		InstructionTypes:   []string{"withdraw"},
		Source:             "solana_jsonparsed_pool_window",
		VerificationStatus: "VERIFIED",
		EvidenceKey:        "liquidity_movement:remove_liquidity:Sig111:12345",
	}

	item, ok := liquidityMovementActorEvidence("solana-mainnet", "TokenMint111", lp, movement)
	if !ok {
		t.Fatal("expected verified liquidity movement to project into actor evidence")
	}
	if item.ActorWallet != "Creator111" || item.Relation != "liquidity_remove_activity" {
		t.Fatalf("unexpected actor relation: %#v", item)
	}
	if item.VerificationStatus != "verified" || item.Signature != "Sig111" || item.Slot != 12345 {
		t.Fatalf("verified transaction references were not preserved: %#v", item)
	}
	if item.TokenAmount != 150 {
		t.Fatalf("expected absolute token movement magnitude, got %v", item.TokenAmount)
	}
	if got, _ := item.Metadata["actor_signed"].(bool); !got {
		t.Fatal("expected signer-backed evidence")
	}
	if got, _ := item.Metadata["creator_role_observed"].(bool); !got {
		t.Fatal("expected direct creator relation to be preserved")
	}
	if item.ObservedAt.Format(time.RFC3339) != "2026-08-10T11:59:00Z" {
		t.Fatalf("expected transaction block time, got %s", item.ObservedAt)
	}
}

func TestLiquidityMovementActorEvidenceNonCreatorDoesNotInventCreatorRelation(t *testing.T) {
	lp := services.LPControlEvidence{
		TokenMint:   "TokenMint111",
		PoolAddress: "Pool111",
		PoolProgram: "Program111",
		ObservedAt:  time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
	}
	movement := services.LiquidityMovementEvidence{
		Kind:               "remove_liquidity",
		Signature:          "Sig222",
		Slot:               22222,
		ActorWallet:        "UnrelatedWallet222",
		PoolAddress:        "Pool111",
		Program:            "Program111",
		SourceWallet:       "Pool111",
		DestinationWallet:  "UnrelatedWallet222",
		CreatorRelated:     false,
		CreatorRelation:    "not_observed",
		VerificationStatus: "VERIFIED",
	}

	item, ok := liquidityMovementActorEvidence("solana-mainnet", "TokenMint111", lp, movement)
	if !ok {
		t.Fatal("expected signer-backed non-creator movement to remain useful actor evidence")
	}
	if got, _ := item.Metadata["creator_role_observed"].(bool); got {
		t.Fatal("non-creator signer must not be promoted to creator/deployer")
	}
	if item.ActorWallet != "UnrelatedWallet222" {
		t.Fatalf("wallet casing/value must remain exact, got %q", item.ActorWallet)
	}
}

func TestLiquidityMovementActorEvidenceRejectsIncompleteReferences(t *testing.T) {
	lp := services.LPControlEvidence{
		TokenMint:   "TokenMint111",
		PoolAddress: "Pool111",
		PoolProgram: "Program111",
		ObservedAt:  time.Now().UTC(),
	}
	movement := services.LiquidityMovementEvidence{
		Kind:               "remove_liquidity",
		ActorWallet:        "Creator111",
		Slot:               33333,
		VerificationStatus: "VERIFIED",
	}
	if _, ok := liquidityMovementActorEvidence("solana-mainnet", "TokenMint111", lp, movement); ok {
		t.Fatal("missing transaction signature must fail closed")
	}
}

func TestLiquidityMovementActorEvidenceKeepsAddAndLockSeparateFromExitRelation(t *testing.T) {
	lp := services.LPControlEvidence{
		TokenMint:   "TokenMint111",
		PoolAddress: "Pool111",
		PoolProgram: "Program111",
		ObservedAt:  time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
	}
	cases := []struct {
		kind     string
		relation string
	}{
		{"add_liquidity", "liquidity_add_activity"},
		{"lock_liquidity", "liquidity_lock_activity"},
	}
	for _, tc := range cases {
		movement := services.LiquidityMovementEvidence{
			Kind: tc.kind, Signature: "Sig-" + tc.kind, Slot: 44444,
			ActorWallet: "Wallet444", PoolAddress: "Pool111", Program: "Program111",
			VerificationStatus: "VERIFIED",
		}
		item, ok := liquidityMovementActorEvidence("solana-mainnet", "TokenMint111", lp, movement)
		if !ok {
			t.Fatalf("expected %s to be persistable", tc.kind)
		}
		if item.Relation != tc.relation {
			t.Fatalf("%s mapped to %s, want %s", tc.kind, item.Relation, tc.relation)
		}
	}
}
