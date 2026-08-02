package services

import (
	"context"
	"testing"
)

func TestNormalizeActorFundingOptionsClampsToHardBounds(t *testing.T) {
	pageSize, maxPages, parseLimit := normalizeActorFundingOptions(ActorFundingOriginOptions{
		PageSize:                  2000,
		MaxPages:                  99,
		OldestTransactionsToParse: 999,
	})
	if pageSize != actorFundingMaxPageSize || maxPages != actorFundingMaxPages || parseLimit != actorFundingMaxParseLimit {
		t.Fatalf("clamped options=%d,%d,%d", pageSize, maxPages, parseLimit)
	}
}

func TestFindActorFundingOriginPublishesConfiguredWindowBoundary(t *testing.T) {
	resetSolanaRPCCachesForTest()
	wallet := "WalletBounded11111111111111111111111111111111"
	blockTime := int64(1700000000)
	fixture := &actorFundingRPCFixture{
		pages: map[string][]SolanaSignatureInfo{
			"": {{Signature: "window-signature", Slot: 901, BlockTime: &blockTime}},
		},
		transactions: map[string]map[string]any{
			"window-signature": outgoingTransaction(wallet, "OtherBounded1111111111111111111111111111111", blockTime),
		},
	}
	server := fixture.server(t)
	defer server.Close()

	result, err := FindActorFundingOrigin(context.Background(), server.URL, wallet, ActorFundingOriginOptions{
		PageSize: 1, MaxPages: 1, OldestTransactionsToParse: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ResultState != ActorFundingResultBounded || result.Boundary.Kind != "configured_signature_window" {
		t.Fatalf("state=%q boundary=%+v", result.ResultState, result.Boundary)
	}
	if !result.Boundary.Raisable || result.Boundary.ReachedHardCeiling || !result.Boundary.ReachedConfiguredWindow {
		t.Fatalf("configured boundary flags=%+v", result.Boundary)
	}
	if result.Boundary.PagesScanned != 1 || result.Boundary.SignaturesWalked != 1 || result.Boundary.OldestSlot != 901 || result.Boundary.OldestSignature != "window-signature" {
		t.Fatalf("configured boundary counters=%+v", result.Boundary)
	}
	if _, ok := ActorFundingOriginEvidence(result, "solana-mainnet"); ok {
		t.Fatal("bounded result without a funding claim must not emit claim evidence")
	}
}

func TestActorFundingHardCeilingIsNotRaisable(t *testing.T) {
	result := ActorFundingOrigin{}
	initializeActorFundingBoundary(&result, actorFundingMaxPageSize, actorFundingMaxPages, actorFundingMaxParseLimit)
	result.PagesScanned = actorFundingMaxPages
	result.SignaturesScanned = actorFundingMaxPageSize * actorFundingMaxPages
	result.TransactionsParsed = actorFundingMaxParseLimit
	syncActorFundingBoundaryCounts(&result)
	markActorFundingPageBoundary(&result, actorFundingMaxPageSize, actorFundingMaxPages)
	if result.ResultState != ActorFundingResultBounded || result.Boundary.Kind != "hard_signature_ceiling" {
		t.Fatalf("state=%q boundary=%+v", result.ResultState, result.Boundary)
	}
	if result.Boundary.Raisable || !result.Boundary.ReachedHardCeiling || result.Boundary.EffectiveSignatureLimit != 20000 {
		t.Fatalf("hard boundary flags=%+v", result.Boundary)
	}
}

func TestFindActorFundingOriginPublishesParseBoundary(t *testing.T) {
	resetSolanaRPCCachesForTest()
	wallet := "WalletParse111111111111111111111111111111111"
	older, newer := int64(1700000000), int64(1700000100)
	fixture := &actorFundingRPCFixture{
		pages: map[string][]SolanaSignatureInfo{
			"": {
				{Signature: "newer-parse", Slot: 1002, BlockTime: &newer},
				{Signature: "older-parse", Slot: 1001, BlockTime: &older},
			},
			"older-parse": {},
		},
		transactions: map[string]map[string]any{
			"older-parse": outgoingTransaction(wallet, "OtherParse111111111111111111111111111111111", older),
			"newer-parse": outgoingTransaction(wallet, "OtherParse222222222222222222222222222222222", newer),
		},
	}
	server := fixture.server(t)
	defer server.Close()

	result, err := FindActorFundingOrigin(context.Background(), server.URL, wallet, ActorFundingOriginOptions{
		PageSize: 2, MaxPages: 2, OldestTransactionsToParse: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ResultState != ActorFundingResultBounded || result.Boundary.Kind != "transaction_parse_limit" {
		t.Fatalf("state=%q boundary=%+v", result.ResultState, result.Boundary)
	}
	if !result.Boundary.ReachedParseLimit || !result.Boundary.Raisable || result.Boundary.TransactionsParsed != 1 {
		t.Fatalf("parse boundary=%+v", result.Boundary)
	}
}

func TestFindActorFundingOriginRPCUnavailableIsMissingWorkerDebt(t *testing.T) {
	result, err := FindActorFundingOrigin(context.Background(), "", "WalletRPC1111111111111111111111111111111111", ActorFundingOriginOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.ResultState != ActorFundingResultMissing || result.Boundary.Kind != "rpc_unavailable" {
		t.Fatalf("state=%q boundary=%+v", result.ResultState, result.Boundary)
	}
	if result.Boundary.EffectiveSignatureLimit != 2000 || result.Boundary.EffectiveParseLimit != 60 {
		t.Fatalf("effective defaults=%+v", result.Boundary)
	}
}

func TestActorAcceptanceFundingClosesBoundedButLeavesMissingOpen(t *testing.T) {
	bounded := actorAcceptanceFunding(ActorFundingOrigin{
		ResultState: ActorFundingResultBounded,
		Boundary: ActorFundingBoundary{
			Kind: "configured_signature_window", PagesScanned: 8, SignaturesWalked: 2000,
			TransactionsParsed: 60, Raisable: true,
		},
	}, "solana-mainnet")
	if bounded.Status != ActorAcceptanceBounded || bounded.EvidenceState != "bounded_by_chain" || len(bounded.Evidence) != 0 {
		t.Fatalf("bounded AC-04=%+v", bounded)
	}

	missing := actorAcceptanceFunding(ActorFundingOrigin{
		Status: "not_investigated", TrailStatus: "not_investigated", ResultState: ActorFundingResultMissing,
	}, "solana-mainnet")
	if missing.Status != ActorAcceptanceNotInvestigated || missing.EvidenceState != "missing_worker_debt" {
		t.Fatalf("missing AC-04=%+v", missing)
	}
}

func TestOperationalAcceptanceCountsBoundedSeparately(t *testing.T) {
	result := ActorAcceptanceResult{Items: []ActorAcceptanceItem{
		{ID: "AC-04", Status: ActorAcceptanceBounded},
		{ID: "AC-01", Status: ActorAcceptancePass},
	}}
	recountOperationalActorAcceptance(&result)
	if result.BoundedCount != 1 || result.NotInvestigatedCount != 0 || result.Status != ActorAcceptanceBounded {
		t.Fatalf("result=%+v", result)
	}
}

func TestActorFundingUnverifiedClaimStillEmitsNoEvidence(t *testing.T) {
	origin := ActorFundingOrigin{
		SourceWallet: "source", DestinationWallet: "destination", Signature: "signature",
		VerificationStatus: "unverified",
	}
	if _, ok := ActorFundingOriginEvidence(origin, "solana-mainnet"); ok {
		t.Fatal("unverified funding claim emitted evidence")
	}
}
