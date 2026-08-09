package services

import (
	"strings"
	"testing"
)

func exitImpactTestAMMKey() string {
	return strings.Join([]string{"HXpGFJGC", "EEFdV31t", "DmjDBaJM", "EB1fKLiA", "oKoWr3Fn", "onid"}, "")
}

func TestBuildExitImpactAssessmentCombinesQuotesWithCanonicalReserveReference(t *testing.T) {
	exit := ExitLiquiditySimulation{
		Available: true,
		Status:    "complete",
		Tiers: []ExitLiquidityTier{
			{RequestedNotionalUSD: 1000, Available: true, EstimatedProceedsUSD: 990, ExecutionShortfallPct: 1, ReferencePriceDropPct: 1, JupiterPriceImpactPct: 0.8, QuoteContextSlot: 102, RouteLabels: []string{"Raydium", "Raydium"}},
			{RequestedNotionalUSD: 10000, Available: true, EstimatedProceedsUSD: 9000, ExecutionShortfallPct: 10, ReferencePriceDropPct: 10, JupiterPriceImpactPct: 9, QuoteContextSlot: 104, RouteLabels: []string{"Orca", "Raydium"}},
			{RequestedNotionalUSD: 100000, Available: true, EstimatedProceedsUSD: 60000, ExecutionShortfallPct: 40, ReferencePriceDropPct: 40, JupiterPriceImpactPct: 35, QuoteContextSlot: 108, RouteLabels: []string{"Meteora"}},
		},
	}
	lp := LPControlEvidence{
		Available: true, Status: "verified", CanonicalPool: true, PoolAddress: "PoolA", PoolProgram: "RaydiumProgram",
		ControlModel: "lp_token", ReadSlot: 100, ReserveLiquidityUSD: 50000, ReserveValueSource: "vault_balances",
		DominantLPSharePct: 45, DominantLPClassification: "locker", LockedLPSharePct: 45, MovementStatus: "stable",
	}

	impact := BuildExitImpactAssessment(exit, lp)
	if !impact.Available || impact.Status != "complete" || impact.Version != ExitImpactVersion {
		t.Fatalf("unexpected impact: %#v", impact)
	}
	if impact.QuotedTierCount != 3 || impact.LargestQuotedNotionalUSD != 100000 {
		t.Fatalf("unexpected quote coverage: %#v", impact)
	}
	if impact.WorstExecutionShortfallPct != 40 || impact.WorstReferencePriceDropPct != 40 || impact.WorstJupiterPriceImpactPct != 35 {
		t.Fatalf("unexpected worst execution metrics: %#v", impact)
	}
	if impact.MaxCanonicalReserveReferencePct != 200 {
		t.Fatalf("max canonical reserve reference=%v want 200", impact.MaxCanonicalReserveReferencePct)
	}
	if impact.MaxObservationSlotSpread != 8 || impact.MaxQuoteContextSlot != 108 {
		t.Fatalf("unexpected slot evidence: %#v", impact)
	}
	if impact.Tiers[0].CanonicalReserveReferencePct != 2 || impact.Tiers[1].CanonicalReserveReferencePct != 20 || impact.Tiers[2].CanonicalReserveReferencePct != 200 {
		t.Fatalf("unexpected reserve references: %#v", impact.Tiers)
	}
	if impact.Tiers[1].UniqueRouteLabelCount != 2 || len(impact.Tiers[1].RouteLabels) != 2 || impact.Tiers[1].RouteLabels[0] != "Orca" {
		t.Fatalf("route labels not normalized: %#v", impact.Tiers[1])
	}
	if impact.LPContext.PoolAddress != "PoolA" || impact.LPContext.LockedLPSharePct != 45 {
		t.Fatalf("LP context missing: %#v", impact.LPContext)
	}
}

func TestBuildExitImpactAssessmentAttributesOnlyExactCanonicalPoolAMMKey(t *testing.T) {
	canonicalPool := exitImpactTestAMMKey()
	otherPool := "11111111111111111111111111111111"
	exit := ExitLiquiditySimulation{Tiers: []ExitLiquidityTier{
		{
			RequestedNotionalUSD: 1000, Available: true,
			RoutePlan: []ExitLiquidityRouteStep{
				{AMMKey: canonicalPool, Label: "Meteora DLMM", Percent: 100},
				{AMMKey: canonicalPool, Label: "Meteora DLMM", Percent: 100},
			},
		},
		{
			RequestedNotionalUSD: 10000, Available: true,
			RoutePlan: []ExitLiquidityRouteStep{{AMMKey: otherPool, Label: "Other", Percent: 100}},
		},
		{
			RequestedNotionalUSD: 100000, Available: true,
			RoutePlan: []ExitLiquidityRouteStep{{AMMKey: "not-a-solana-key", Label: "Unknown", Percent: 100}},
		},
	}}
	lp := LPControlEvidence{Available: true, CanonicalPool: true, PoolAddress: canonicalPool, ReserveLiquidityUSD: 50000}
	impact := BuildExitImpactAssessment(exit, lp)

	if impact.Version != "koschei-exit-impact-v3" {
		t.Fatalf("version=%q", impact.Version)
	}
	if impact.RouteAttributedTierCount != 2 || impact.CanonicalPoolMatchedTierCount != 1 || !impact.CanonicalPoolObservedInAnyRoute || impact.RouteAttributionStatus != "partial" {
		t.Fatalf("unexpected route attribution aggregate: %#v", impact)
	}
	first := impact.Tiers[0]
	if !first.CanonicalPoolObservedInRoute || first.CanonicalPoolRouteStatus != "canonical_pool_observed_in_returned_route_plan" || first.CanonicalPoolRouteMatchCount != 1 {
		t.Fatalf("exact canonical match missing: %#v", first)
	}
	if first.UniqueRouteAMMKeyCount != 1 || len(first.RouteAMMKeys) != 1 || first.RouteAMMKeys[0] != canonicalPool {
		t.Fatalf("AMM keys not canonicalized: %#v", first)
	}
	second := impact.Tiers[1]
	if second.CanonicalPoolObservedInRoute || second.CanonicalPoolRouteStatus != "canonical_pool_not_observed_in_returned_route_plan" {
		t.Fatalf("non-match overstated: %#v", second)
	}
	third := impact.Tiers[2]
	if third.CanonicalPoolRouteStatus != "route_keys_unavailable" || third.UniqueRouteAMMKeyCount != 0 {
		t.Fatalf("invalid route key accepted: %#v", third)
	}
	if !strings.Contains(strings.Join(second.Limitations, " "), "does not prove") {
		t.Fatalf("missing non-match limitation: %#v", second.Limitations)
	}
}

func TestBuildExitImpactAssessmentDoesNotInventCanonicalReserveRatioWithoutEvidence(t *testing.T) {
	exit := ExitLiquiditySimulation{Tiers: []ExitLiquidityTier{{RequestedNotionalUSD: 1000, Available: true, ExecutionShortfallPct: 5}}}
	impact := BuildExitImpactAssessment(exit, LPControlEvidence{Available: false, Status: "source_unavailable"})
	if !impact.Available || impact.Status != "quote_complete_lp_reference_unavailable" {
		t.Fatalf("unexpected impact: %#v", impact)
	}
	if impact.Tiers[0].CanonicalReserveReferencePct != 0 || impact.MaxCanonicalReserveReferencePct != 0 {
		t.Fatalf("reserve ratio invented without evidence: %#v", impact)
	}
	joined := strings.Join(impact.Limitations, " ")
	if !strings.Contains(joined, "Jupiter may route across different or multiple liquidity venues") {
		t.Fatalf("missing route/pool separation limitation: %q", joined)
	}
}

func TestBuildExitImpactAssessmentCanExposeLPReferenceWhenQuotesAreUnavailable(t *testing.T) {
	exit := ExitLiquiditySimulation{Tiers: []ExitLiquidityTier{{RequestedNotionalUSD: 1000, Available: false, Status: "quote_unavailable"}}}
	lp := LPControlEvidence{Available: true, CanonicalPool: true, ReserveLiquidityUSD: 25000, ReadSlot: 55, Status: "verified"}
	impact := BuildExitImpactAssessment(exit, lp)
	if impact.Available || impact.Status != "lp_reference_only" {
		t.Fatalf("unexpected LP-only impact: %#v", impact)
	}
	if impact.Tiers[0].Status != "quote_unavailable_reserve_reference_only" || impact.Tiers[0].CanonicalReserveReferencePct != 4 {
		t.Fatalf("unexpected LP-only tier: %#v", impact.Tiers[0])
	}
	if len(impact.Tiers[0].Limitations) == 0 {
		t.Fatal("missing quote-unavailable limitation")
	}
}

func TestBuildExitImpactAssessmentWithholdsSlotSpreadWhenEitherSlotMissing(t *testing.T) {
	exit := ExitLiquiditySimulation{Tiers: []ExitLiquidityTier{{RequestedNotionalUSD: 1000, Available: true, QuoteContextSlot: 0}}}
	lp := LPControlEvidence{Available: true, CanonicalPool: true, ReserveLiquidityUSD: 10000, ReadSlot: 88}
	impact := BuildExitImpactAssessment(exit, lp)
	if impact.Tiers[0].ObservationSlotSpread != 0 || impact.MaxObservationSlotSpread != 0 {
		t.Fatalf("slot spread invented: %#v", impact)
	}
}
