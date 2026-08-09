package services

import (
	"math"
	"sort"
	"strings"
)

// BuildExitImpactAssessment fuses two explicitly separate evidence surfaces:
// Jupiter read-only execution quotes and the canonical pool LP-control/reserve
// snapshot. Route attribution is exact-address matching against the returned
// quote plan only; it does not claim that an unexecuted quote later executed.
func BuildExitImpactAssessment(exit ExitLiquiditySimulation, lp LPControlEvidence) ExitImpactAssessment {
	out := ExitImpactAssessment{
		Version:            ExitImpactVersion,
		Status:             "unavailable",
		RequestedTierCount: len(exit.Tiers),
		LPContext:          exitImpactLPContext(lp),
		Tiers:              []ExitImpactTier{},
		Limitations:        []string{},
	}
	reserveUSD := lp.ReserveLiquidityUSD
	reserveObserved := lp.Available && lp.CanonicalPool && reserveUSD > 0
	canonicalPool := strings.TrimSpace(lp.PoolAddress)
	if !reserveObserved {
		out.Limitations = append(out.Limitations, "Canonical pool reserve USD evidence is unavailable or incomplete; reserve-reference ratios are withheld.")
	}
	out.Limitations = append(out.Limitations,
		"Canonical reserve reference percentages are context only; Jupiter may route across different or multiple liquidity venues.",
		"AMM-key attribution describes the returned Jupiter quote plan only; it does not prove that an unexecuted quote was later executed.",
	)

	for _, tier := range exit.Tiers {
		impactTier := ExitImpactTier{
			RequestedNotionalUSD:     tier.RequestedNotionalUSD,
			QuoteAvailable:           tier.Available,
			Status:                   "unavailable",
			QuoteContextSlot:         tier.QuoteContextSlot,
			LPReadSlot:               lp.ReadSlot,
			RouteLabels:              normalizedExitImpactLabels(tier.RouteLabels),
			RouteAMMKeys:             normalizedExitImpactAMMKeys(tier.RoutePlan),
			CanonicalPoolRouteStatus: "quote_unavailable",
			Limitations:              []string{},
		}
		impactTier.UniqueRouteLabelCount = len(impactTier.RouteLabels)
		impactTier.UniqueRouteAMMKeyCount = len(impactTier.RouteAMMKeys)
		if tier.Available && len(impactTier.RouteAMMKeys) > 0 {
			out.RouteAttributedTierCount++
		}
		if lp.ReadSlot > 0 && tier.QuoteContextSlot > 0 {
			impactTier.ObservationSlotSpread = absoluteSlotSpread(lp.ReadSlot, tier.QuoteContextSlot)
			if impactTier.ObservationSlotSpread > out.MaxObservationSlotSpread {
				out.MaxObservationSlotSpread = impactTier.ObservationSlotSpread
			}
		}
		if tier.QuoteContextSlot > out.MaxQuoteContextSlot {
			out.MaxQuoteContextSlot = tier.QuoteContextSlot
		}
		if reserveObserved && tier.RequestedNotionalUSD > 0 {
			impactTier.CanonicalReserveReferencePct = roundExitImpact(tier.RequestedNotionalUSD/reserveUSD*100, 4)
			if impactTier.CanonicalReserveReferencePct > out.MaxCanonicalReserveReferencePct {
				out.MaxCanonicalReserveReferencePct = impactTier.CanonicalReserveReferencePct
			}
		}

		if tier.Available {
			impactTier.EstimatedProceedsUSD = tier.EstimatedProceedsUSD
			impactTier.ExecutionShortfallPct = tier.ExecutionShortfallPct
			impactTier.ReferencePriceDropPct = tier.ReferencePriceDropPct
			impactTier.JupiterPriceImpactPct = tier.JupiterPriceImpactPct
			out.QuotedTierCount++
			if tier.RequestedNotionalUSD > out.LargestQuotedNotionalUSD {
				out.LargestQuotedNotionalUSD = tier.RequestedNotionalUSD
			}
			out.WorstExecutionShortfallPct = math.Max(out.WorstExecutionShortfallPct, tier.ExecutionShortfallPct)
			out.WorstReferencePriceDropPct = math.Max(out.WorstReferencePriceDropPct, tier.ReferencePriceDropPct)
			out.WorstJupiterPriceImpactPct = math.Max(out.WorstJupiterPriceImpactPct, tier.JupiterPriceImpactPct)
			if reserveObserved {
				impactTier.Status = "quote_plus_canonical_reserve_reference"
			} else {
				impactTier.Status = "quote_only"
			}
		} else if reserveObserved {
			impactTier.Status = "quote_unavailable_reserve_reference_only"
			impactTier.Limitations = append(impactTier.Limitations, "Jupiter did not provide a usable execution quote for this tier.")
		}

		switch {
		case !tier.Available:
			impactTier.CanonicalPoolRouteStatus = "quote_unavailable"
		case len(impactTier.RouteAMMKeys) == 0:
			impactTier.CanonicalPoolRouteStatus = "route_keys_unavailable"
			impactTier.Limitations = append(impactTier.Limitations, "The returned quote did not expose a usable AMM account identity for route attribution.")
		case !lp.CanonicalPool || canonicalPool == "":
			impactTier.CanonicalPoolRouteStatus = "canonical_pool_unavailable"
		case true:
			for _, ammKey := range impactTier.RouteAMMKeys {
				if ammKey == canonicalPool {
					impactTier.CanonicalPoolRouteMatchCount++
				}
			}
			if impactTier.CanonicalPoolRouteMatchCount > 0 {
				impactTier.CanonicalPoolObservedInRoute = true
				impactTier.CanonicalPoolRouteStatus = "canonical_pool_observed_in_returned_route_plan"
				out.CanonicalPoolMatchedTierCount++
				out.CanonicalPoolObservedInAnyRoute = true
			} else {
				impactTier.CanonicalPoolRouteStatus = "canonical_pool_not_observed_in_returned_route_plan"
				impactTier.Limitations = append(impactTier.Limitations, "The canonical pool address was not present in the returned quote-plan AMM keys; this does not prove that a later quote or execution could not use it.")
			}
		}
		out.Tiers = append(out.Tiers, impactTier)
	}

	out.Available = out.QuotedTierCount > 0
	switch {
	case out.QuotedTierCount == 0:
		out.RouteAttributionStatus = "unavailable"
	case out.RouteAttributedTierCount == out.QuotedTierCount:
		out.RouteAttributionStatus = "complete"
	case out.RouteAttributedTierCount > 0:
		out.RouteAttributionStatus = "partial"
	default:
		out.RouteAttributionStatus = "unavailable"
	}
	switch {
	case out.QuotedTierCount == len(exit.Tiers) && len(exit.Tiers) > 0 && reserveObserved:
		out.Status = "complete"
	case out.QuotedTierCount == len(exit.Tiers) && len(exit.Tiers) > 0:
		out.Status = "quote_complete_lp_reference_unavailable"
	case out.QuotedTierCount > 0 && reserveObserved:
		out.Status = "partial"
	case out.QuotedTierCount > 0:
		out.Status = "quote_partial_lp_reference_unavailable"
	case reserveObserved:
		out.Status = "lp_reference_only"
	default:
		out.Status = "unavailable"
	}
	return out
}

func exitImpactLPContext(lp LPControlEvidence) ExitImpactLPContext {
	return ExitImpactLPContext{
		Available:                 lp.Available,
		Status:                    strings.TrimSpace(lp.Status),
		PoolAddress:               strings.TrimSpace(lp.PoolAddress),
		PoolProgram:               strings.TrimSpace(lp.PoolProgram),
		PoolType:                  strings.TrimSpace(lp.PoolType),
		ControlModel:              strings.TrimSpace(lp.ControlModel),
		CanonicalPool:             lp.CanonicalPool,
		ReadSlot:                  lp.ReadSlot,
		ReserveLiquidityUSD:       lp.ReserveLiquidityUSD,
		ReserveValueSource:        strings.TrimSpace(lp.ReserveValueSource),
		DominantLPSharePct:        lp.DominantLPSharePct,
		DominantLPClassification:  strings.TrimSpace(lp.DominantLPClassification),
		CreatorRelation:           strings.TrimSpace(lp.CreatorRelation),
		CreatorLPSharePct:         lp.CreatorLPSharePct,
		BurnedSharePct:            lp.BurnedSharePct,
		LockedLPSharePct:          lp.LockedLPSharePct,
		PermanentLockedSharePct:   lp.PermanentLockedSharePct,
		MovementStatus:            strings.TrimSpace(lp.MovementStatus),
		PositionEnumerationStatus: strings.TrimSpace(lp.PositionEnumerationStatus),
	}
}

func normalizedExitImpactLabels(labels []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

func normalizedExitImpactAMMKeys(plan []ExitLiquidityRouteStep) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, step := range plan {
		key := strings.TrimSpace(step.AMMKey)
		if !looksLikeExitRouteAMMKey(key) || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func looksLikeExitRouteAMMKey(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 32 || len(value) > 44 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", char) {
			return false
		}
	}
	return true
}

func absoluteSlotSpread(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return b - a
}

func roundExitImpact(value float64, decimals int) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	factor := math.Pow10(decimals)
	return math.Round(value*factor) / factor
}
