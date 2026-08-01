package services

import (
	"testing"
	"time"
)

func TestBuildActorTokenLifecycleSnapshotSeparatesAgeFromLifetime(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	observed := created.Add(10 * 24 * time.Hour)
	item := BuildActorTokenLifecycleSnapshot(ActorTokenLifecycleInput{
		Network:             "solana-mainnet",
		ActorWallet:         "creator",
		Mint:                "mint",
		CreatedOnChainAt:    created,
		ObservedAt:          observed,
		CurrentLiquidityUSD: 1250,
	})
	if item.FateStatus != ActorTokenFateActive {
		t.Fatalf("expected active fate, got %q", item.FateStatus)
	}
	if !item.AgeAvailable || item.AgeDays != 10 {
		t.Fatalf("expected 10 day age, got available=%v days=%v", item.AgeAvailable, item.AgeDays)
	}
	if item.VerifiedLifetimeAvailable {
		t.Fatal("active age must not be presented as verified lifetime")
	}
}

func TestDeriveActorTokenLifecycleRequiresObservedTransition(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	firstLiquid := created.Add(24 * time.Hour)
	lastLiquid := created.Add(4 * 24 * time.Hour)
	inactiveSince := created.Add(5 * 24 * time.Hour)
	item := deriveActorTokenLifecycle(ActorTokenLifecycleObservation{
		CreatedOnChainAt:      &created,
		FirstObservedAt:       firstLiquid,
		LastObservedAt:        inactiveSince,
		FirstLiquidObservedAt: &firstLiquid,
		LastLiquidObservedAt:  &lastLiquid,
		CurrentInactiveSince:  &inactiveSince,
		FateStatus:            ActorTokenFateInactiveOrDead,
	})
	if !item.VerifiedLifetimeAvailable {
		t.Fatal("expected verified lifetime after liquid-to-inactive transition")
	}
	if item.VerifiedLifetimeDays != 5 {
		t.Fatalf("expected five day lifetime, got %v", item.VerifiedLifetimeDays)
	}
	if item.VerifiedLiquidLifetimeDays != 4 {
		t.Fatalf("expected four liquid days, got %v", item.VerifiedLiquidLifetimeDays)
	}
}

func TestSummarizeActorTokenLifecycles(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	active := BuildActorTokenLifecycleSnapshot(ActorTokenLifecycleInput{
		ActorWallet: "creator", Mint: "active", CreatedOnChainAt: created,
		ObservedAt: created.Add(10 * 24 * time.Hour), CurrentLiquidityUSD: 100,
	})
	firstLiquid := created.Add(24 * time.Hour)
	lastLiquid := created.Add(3 * 24 * time.Hour)
	inactiveSince := created.Add(4 * 24 * time.Hour)
	dead := deriveActorTokenLifecycle(ActorTokenLifecycleObservation{
		ActorWallet: "creator", Mint: "dead", CreatedOnChainAt: &created,
		FirstObservedAt: firstLiquid, LastObservedAt: inactiveSince,
		FirstLiquidObservedAt: &firstLiquid, LastLiquidObservedAt: &lastLiquid,
		FirstInactiveObservedAt: &inactiveSince, CurrentInactiveSince: &inactiveSince,
		FateStatus: ActorTokenFateInactiveOrDead,
	})
	summary := SummarizeActorTokenLifecycles([]ActorTokenLifecycleObservation{active, dead})
	if summary.ActiveTokens != 1 || summary.InactiveOrDeadTokens != 1 {
		t.Fatalf("unexpected fate counts: %+v", summary)
	}
	if !summary.AverageLifetimeAvailable || summary.AverageLifetimeDays != 4 {
		t.Fatalf("unexpected verified lifetime summary: %+v", summary)
	}
	if summary.AverageObservedAgeDays != 7 {
		t.Fatalf("expected seven day average observed age, got %v", summary.AverageObservedAgeDays)
	}
}
