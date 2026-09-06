package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestBuildCreatorTokenObservedPathsRequiresVerifiedMintAndTransfer(t *testing.T) {
	observed := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	portfolio := newActorCreatedMintIntegrationRun("Creator111")
	portfolio.VerifiedCandidates = []services.ActorCreatedMintCandidate{{Mint: "MintA"}}

	flow := newAddressFlowReport("Creator111", "solana-mainnet")
	flow.Transfers = []addressFlowTransfer{
		{
			Direction: "outbound", AssetType: "SPL_TOKEN", TokenMint: "MintA",
			Counterparty: "Dex111", Signature: "sig-a", Slot: 101, ObservedAt: observed,
			TokenAmount: 25, VerificationStatus: "verified", Source: "solana_jsonparsed_transaction",
		},
		{
			Direction: "outbound", AssetType: "SPL_TOKEN", TokenMint: "MintUnverified",
			Counterparty: "Dex111", Signature: "sig-b", Slot: 102, ObservedAt: observed.Add(time.Minute),
			VerificationStatus: "verified",
		},
		{
			Direction: "outbound", AssetType: "SPL_TOKEN", TokenMint: "MintA",
			Counterparty: "Dex111", Signature: "sig-c", Slot: 103, ObservedAt: observed.Add(2 * time.Minute),
			VerificationStatus: "observed",
		},
	}
	interactions := newAddressInteractionsReport("Creator111")
	interactions.Interactions = []addressInteraction{{
		Address: "Dex111", InteractionKind: services.WalletEntityKindDEX,
		Verification: "provider_verified_taxonomy_and_direct_onchain_flow",
	}}
	outcomes := newCreatorOutcomeHistoryReport("Creator111")
	outcomes.Outcomes = []creatorTokenOutcome{{Mint: "MintA", FateStatus: services.ActorTokenFateInactiveOrDead, LifecycleStatus: "verified_liquid_to_inactive_transition"}}

	report := buildCreatorTokenObservedPaths("Creator111", portfolio, flow, interactions, outcomes)
	if report.ObservedPathCount != 1 {
		t.Fatalf("observed path count = %d", report.ObservedPathCount)
	}
	path := report.Paths[0]
	if path.Mint != "MintA" || path.Signature != "sig-a" || path.Slot != 101 {
		t.Fatalf("unexpected path: %+v", path)
	}
	if path.CounterpartyKind != services.WalletEntityKindDEX {
		t.Fatalf("counterparty kind = %q", path.CounterpartyKind)
	}
	if path.LifecycleFate != services.ActorTokenFateInactiveOrDead {
		t.Fatalf("lifecycle fate = %q", path.LifecycleFate)
	}
	if path.SaleClaimed || path.RugClaimed || path.WrongdoingClaimed {
		t.Fatalf("unsupported claim emitted: %+v", path)
	}
}

func TestBuildCreatorTokenObservedPathsUnknownEndpointRemainsUnknown(t *testing.T) {
	observed := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	portfolio := newActorCreatedMintIntegrationRun("Creator222")
	portfolio.VerifiedCandidates = []services.ActorCreatedMintCandidate{{Mint: "MintB"}}
	flow := newAddressFlowReport("Creator222", "solana-mainnet")
	flow.FlowComplete = false
	flow.Transfers = []addressFlowTransfer{{
		Direction: "outbound", AssetType: "SPL_TOKEN", TokenMint: "MintB",
		Counterparty: "Unknown111", Signature: "sig-u", Slot: 201, ObservedAt: observed,
		VerificationStatus: "verified",
	}}

	report := buildCreatorTokenObservedPaths("Creator222", portfolio, flow, newAddressInteractionsReport("Creator222"), newCreatorOutcomeHistoryReport("Creator222"))
	if report.Status != "verified_creator_token_paths_observed" {
		t.Fatalf("status = %q", report.Status)
	}
	if report.UnknownEndpointCount != 1 || report.ClassifiedEndpointCount != 0 {
		t.Fatalf("unexpected endpoint counts: %+v", report)
	}
	if report.Paths[0].CounterpartyKind != services.WalletEntityKindUnknown {
		t.Fatalf("unknown endpoint was relabeled: %+v", report.Paths[0])
	}
	if len(report.Limitations) == 0 {
		t.Fatal("expected bounded-flow limitation")
	}
}

func TestBuildCreatorTokenObservedPathsNoVerifiedMintWithholdsPath(t *testing.T) {
	flow := newAddressFlowReport("Creator333", "solana-mainnet")
	flow.Transfers = []addressFlowTransfer{{
		Direction: "outbound", AssetType: "SPL_TOKEN", TokenMint: "MintC",
		Counterparty: "Dex333", Signature: "sig-c", Slot: 301, ObservedAt: time.Now().UTC(),
		VerificationStatus: "verified",
	}}
	report := buildCreatorTokenObservedPaths("Creator333", newActorCreatedMintIntegrationRun("Creator333"), flow, newAddressInteractionsReport("Creator333"), newCreatorOutcomeHistoryReport("Creator333"))
	if report.ObservedPathCount != 0 {
		t.Fatalf("path emitted without verified creator mint: %+v", report.Paths)
	}
	if value, _ := report.Policy["rug_claimed"].(bool); value {
		t.Fatal("rug claim must remain disabled")
	}
	if value, _ := report.Policy["neon_persistence"].(bool); value {
		t.Fatal("Neon persistence must remain disabled")
	}
}
