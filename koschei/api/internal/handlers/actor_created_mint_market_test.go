package handlers

import (
	"context"
	"testing"

	"koschei/api/internal/services"
)

func TestApplyActorTokenMarketSnapshotDistinguishesUnavailableFromDead(t *testing.T) {
	candidate := services.ActorCreatedMintCandidate{Mint: "mint"}
	fate := applyActorTokenMarketSnapshot(&candidate, services.TokenMarketSnapshot{Status: "market_request_failed"})
	if fate.Status != actorTokenFateMarketDataUnavailable || candidate.FateStatus != actorTokenFateMarketDataUnavailable {
		t.Fatalf("unavailable market was classified as %q", candidate.FateStatus)
	}
	if candidate.LiquidityEvidenceAvailable || fate.LifecycleEligible {
		t.Fatal("unavailable market must not create lifecycle evidence")
	}
}

func TestApplyActorTokenMarketSnapshotClassifiesExplicitObservations(t *testing.T) {
	cases := []struct {
		name   string
		market services.TokenMarketSnapshot
		want   string
	}{
		{name: "positive liquidity", market: services.TokenMarketSnapshot{Status: "verified_market_snapshot", PairCount: 2, LiquidityUSD: 1250}, want: services.ActorTokenFateActive},
		{name: "verified zero liquidity", market: services.TokenMarketSnapshot{Status: "verified_market_snapshot", PairCount: 1}, want: services.ActorTokenFateInactiveOrDead},
		{name: "no pair returned", market: services.TokenMarketSnapshot{Status: "no_solana_pairs"}, want: services.ActorTokenFateInactiveOrDead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := services.ActorCreatedMintCandidate{Mint: "mint"}
			fate := applyActorTokenMarketSnapshot(&candidate, tc.market)
			if fate.Status != tc.want || candidate.FateStatus != tc.want {
				t.Fatalf("got %q want %q", candidate.FateStatus, tc.want)
			}
			if !candidate.LiquidityEvidenceAvailable || !fate.LifecycleEligible {
				t.Fatal("explicit market observation must be lifecycle eligible")
			}
		})
	}
}

func TestObservedLaunchesRemainObservedAndDeduplicateVerifiedMints(t *testing.T) {
	out := newActorCreatedMintIntegrationRun("wallet")
	out.VerifiedCandidates = []services.ActorCreatedMintCandidate{{Mint: "verified", VerificationStatus: "verified"}}
	observed := []map[string]any{
		{"target": "verified", "signature": "duplicate"},
		{"target": "observed", "signature": "sig-observed"},
	}
	appendObservedCreatorLaunchRows(context.Background(), &out, observed, func(context.Context, string) services.TokenMarketSnapshot {
		return services.TokenMarketSnapshot{Status: "market_request_failed"}
	})
	if len(out.VerifiedCandidates) != 1 {
		t.Fatalf("observation store changed verified candidates: %d", len(out.VerifiedCandidates))
	}
	if out.ObservedStoreCandidatesMerged != 1 || len(out.Discovery.Candidates) != 1 {
		t.Fatalf("merged=%d discovery=%d", out.ObservedStoreCandidatesMerged, len(out.Discovery.Candidates))
	}
	candidate := out.Discovery.Candidates[0]
	if candidate.VerificationStatus != "koschei_observed" || candidate.Source != "koschei_observation_store" {
		t.Fatalf("observation was mislabeled: %+v", candidate)
	}
	if candidate.FateStatus != actorTokenFateMarketDataUnavailable || out.MarketDataUnavailableCandidates != 1 {
		t.Fatalf("unavailable fate was not published honestly: %+v", candidate)
	}
}

func TestActorCreatedMintVerificationCandidatesExcludeObservationStore(t *testing.T) {
	candidates := []services.ActorCreatedMintCandidate{
		{Mint: "helius", Source: "helius_enhanced_transactions", Signature: "sig-1"},
		{Mint: "stored", Source: "koschei_observation_store", Signature: "sig-2"},
	}
	got := actorCreatedMintVerificationCandidates(candidates)
	if len(got) != 1 || got[0].Mint != "helius" {
		t.Fatalf("verification queue=%+v", got)
	}
}
