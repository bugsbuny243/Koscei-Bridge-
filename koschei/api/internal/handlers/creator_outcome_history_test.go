package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestBuildCreatorOutcomeHistoryPreservesEvidenceBoundaries(t *testing.T) {
	created := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	observed := created.Add(72 * time.Hour)
	inactiveSince := observed
	liquidAt := created.Add(2 * time.Hour)

	portfolio := newActorCreatedMintIntegrationRun("Creator111")
	portfolio.VerifiedCandidates = []services.ActorCreatedMintCandidate{{Mint: "MintActive"}, {Mint: "MintInactive"}}
	portfolio.LifecycleObservations = []services.ActorTokenLifecycleObservation{
		{
			Network: "solana-mainnet", ActorWallet: "Creator111", Mint: "MintActive",
			CreationSignature: "sig-active", CreationSlot: 11, CreatedOnChainAt: &created,
			LastObservedAt: observed, CurrentLiquidityUSD: 12000, CurrentPriceUSD: 0.4,
			FateStatus: services.ActorTokenFateActive, AgeAvailable: true, AgeDays: 3,
			LifecycleStatus: "active_age_observed",
		},
		{
			Network: "solana-mainnet", ActorWallet: "Creator111", Mint: "MintInactive",
			CreationSignature: "sig-inactive", CreationSlot: 12, CreatedOnChainAt: &created,
			FirstLiquidObservedAt: &liquidAt, LastLiquidObservedAt: &liquidAt,
			CurrentInactiveSince: &inactiveSince, LastObservedAt: observed,
			CurrentLiquidityUSD: 0, CurrentPriceUSD: 0,
			FateStatus: services.ActorTokenFateInactiveOrDead, AgeAvailable: true, AgeDays: 3,
			VerifiedLifetimeAvailable: true, VerifiedLifetimeDays: 3,
			LifecycleStatus: "verified_liquid_to_inactive_transition",
		},
	}

	report := buildCreatorOutcomeHistory("Creator111", portfolio)
	if report.Status != "verified_creator_outcomes_available" {
		t.Fatalf("status = %q", report.Status)
	}
	if report.OutcomeCount != 2 || report.ActiveCount != 1 || report.InactiveOrDeadCount != 1 {
		t.Fatalf("unexpected counts: %+v", report)
	}
	if report.VerifiedLifetimeSampleCount != 1 {
		t.Fatalf("verified lifetime samples = %d", report.VerifiedLifetimeSampleCount)
	}
	if value, _ := report.Policy["rug_claimed"].(bool); value {
		t.Fatal("creator outcome history must not claim rug status")
	}
	if value, _ := report.Policy["neon_persistence"].(bool); value {
		t.Fatal("creator outcome history must not use Neon persistence")
	}
	for _, outcome := range report.Outcomes {
		if outcome.RugClaimed || outcome.WrongdoingClaimed {
			t.Fatalf("unsupported claim emitted for %s", outcome.Mint)
		}
		if outcome.EvidenceStatus != "verified_creator_mint_plus_market_snapshot" {
			t.Fatalf("evidence status = %q", outcome.EvidenceStatus)
		}
	}
}

func TestBuildCreatorOutcomeHistoryReportsMarketGapWithoutInventingFate(t *testing.T) {
	portfolio := newActorCreatedMintIntegrationRun("Creator222")
	portfolio.VerifiedCandidates = []services.ActorCreatedMintCandidate{{Mint: "MintNoMarket"}}
	portfolio.MarketDataUnavailableCandidates = 1

	report := buildCreatorOutcomeHistory("Creator222", portfolio)
	if report.Status != "verified_creator_tokens_market_outcome_unavailable" {
		t.Fatalf("status = %q", report.Status)
	}
	if report.OutcomeCount != 0 || report.InactiveOrDeadCount != 0 {
		t.Fatalf("market gap must not invent inactive outcome: %+v", report)
	}
	if len(report.Limitations) == 0 {
		t.Fatal("expected explicit market-data limitation")
	}
}

func TestBuildCreatorOutcomeHistoryEmptyPortfolio(t *testing.T) {
	report := buildCreatorOutcomeHistory("Creator333", newActorCreatedMintIntegrationRun("Creator333"))
	if report.Status != "no_verified_creator_outcomes" {
		t.Fatalf("status = %q", report.Status)
	}
	if report.OutcomeCount != 0 || len(report.Outcomes) != 0 {
		t.Fatalf("unexpected outcomes: %+v", report.Outcomes)
	}
}
