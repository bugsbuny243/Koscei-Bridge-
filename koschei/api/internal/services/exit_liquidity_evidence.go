package services

import "time"

const ExitImpactVersion = "koschei-exit-impact-v3"

// ExitLiquidityRouteStep is one Jupiter-returned quote-plan step. AMMKey is the
// pool/AMM account identity returned by Jupiter for that step; it describes the
// quote plan only and is not proof that an unexecuted quote was later executed.
type ExitLiquidityRouteStep struct {
	AMMKey  string `json:"amm_key,omitempty"`
	Label   string `json:"label,omitempty"`
	Percent int    `json:"percent,omitempty"`
}

// ExitLiquidityTier is one read-only Jupiter ExactIn quote. It is an estimate,
// not a guaranteed liquidation price and never creates a swap transaction.
type ExitLiquidityTier struct {
	RequestedNotionalUSD    float64                  `json:"requested_notional_usd"`
	Available               bool                     `json:"available"`
	Status                  string                   `json:"status"`
	InputTokenAmount        float64                  `json:"input_token_amount,omitempty"`
	InputAmountRaw          string                   `json:"input_amount_raw,omitempty"`
	OutputAmountRaw         string                   `json:"output_amount_raw,omitempty"`
	EstimatedProceedsUSD    float64                  `json:"estimated_proceeds_usd,omitempty"`
	ExecutionShortfallUSD   float64                  `json:"execution_shortfall_usd,omitempty"`
	ExecutionShortfallPct   float64                  `json:"execution_shortfall_pct,omitempty"`
	ProceedsToNotionalPct   float64                  `json:"proceeds_to_notional_pct,omitempty"`
	EffectiveExecutionPrice float64                  `json:"effective_execution_price_usd,omitempty"`
	ReferencePriceDropPct   float64                  `json:"reference_price_drop_pct,omitempty"`
	JupiterPriceImpactPct   float64                  `json:"jupiter_price_impact_pct,omitempty"`
	QuoteContextSlot        uint64                   `json:"quote_context_slot,omitempty"`
	RouteLabels             []string                 `json:"route_labels"`
	RoutePlan               []ExitLiquidityRouteStep `json:"route_plan"`
	ObservedAt              time.Time                `json:"observed_at,omitempty"`
	Limitations             []string                 `json:"limitations"`
}

// ExitImpactLPContext projects only the LP-control fields that explain the
// canonical pool's reserve and control surface. It is context, not a claim that
// a Jupiter route executed through this exact pool.
type ExitImpactLPContext struct {
	Available                 bool    `json:"available"`
	Status                    string  `json:"status"`
	PoolAddress               string  `json:"pool_address,omitempty"`
	PoolProgram               string  `json:"pool_program,omitempty"`
	PoolType                  string  `json:"pool_type,omitempty"`
	ControlModel              string  `json:"control_model,omitempty"`
	CanonicalPool             bool    `json:"canonical_pool"`
	ReadSlot                  uint64  `json:"read_slot,omitempty"`
	ReserveLiquidityUSD       float64 `json:"reserve_liquidity_usd,omitempty"`
	ReserveValueSource        string  `json:"reserve_value_source,omitempty"`
	DominantLPSharePct        float64 `json:"dominant_lp_share_pct,omitempty"`
	DominantLPClassification  string  `json:"dominant_lp_classification,omitempty"`
	CreatorRelation           string  `json:"creator_relation,omitempty"`
	CreatorLPSharePct         float64 `json:"creator_lp_share_pct,omitempty"`
	BurnedSharePct            float64 `json:"burned_share_pct,omitempty"`
	LockedLPSharePct          float64 `json:"locked_lp_share_pct,omitempty"`
	PermanentLockedSharePct   float64 `json:"permanent_locked_share_pct,omitempty"`
	MovementStatus            string  `json:"movement_status,omitempty"`
	PositionEnumerationStatus string  `json:"position_enumeration_status,omitempty"`
}

// ExitImpactTier correlates one read-only execution quote with separately
// observed LP context and, when available, returned Jupiter AMM identities.
type ExitImpactTier struct {
	RequestedNotionalUSD         float64  `json:"requested_notional_usd"`
	QuoteAvailable               bool     `json:"quote_available"`
	Status                       string   `json:"status"`
	EstimatedProceedsUSD         float64  `json:"estimated_proceeds_usd,omitempty"`
	ExecutionShortfallPct        float64  `json:"execution_shortfall_pct,omitempty"`
	ReferencePriceDropPct        float64  `json:"reference_price_drop_pct,omitempty"`
	JupiterPriceImpactPct        float64  `json:"jupiter_price_impact_pct,omitempty"`
	CanonicalReserveReferencePct float64  `json:"canonical_reserve_reference_pct,omitempty"`
	QuoteContextSlot             uint64   `json:"quote_context_slot,omitempty"`
	LPReadSlot                   uint64   `json:"lp_read_slot,omitempty"`
	ObservationSlotSpread        uint64   `json:"observation_slot_spread,omitempty"`
	UniqueRouteLabelCount        int      `json:"unique_route_label_count"`
	UniqueRouteAMMKeyCount       int      `json:"unique_route_amm_key_count"`
	RouteLabels                  []string `json:"route_labels"`
	RouteAMMKeys                 []string `json:"route_amm_keys"`
	CanonicalPoolRouteStatus     string   `json:"canonical_pool_route_status"`
	CanonicalPoolObservedInRoute bool     `json:"canonical_pool_observed_in_route"`
	CanonicalPoolRouteMatchCount int      `json:"canonical_pool_route_match_count"`
	Limitations                  []string `json:"limitations"`
}

// ExitImpactAssessment combines measured Jupiter execution outcomes with a
// separately observed canonical LP-control/reserve context. It does not produce
// a security verdict. Route attribution applies only to the returned quote plan.
type ExitImpactAssessment struct {
	Version                         string              `json:"version"`
	Available                       bool                `json:"available"`
	Status                          string              `json:"status"`
	QuotedTierCount                 int                 `json:"quoted_tier_count"`
	RequestedTierCount              int                 `json:"requested_tier_count"`
	LargestQuotedNotionalUSD        float64             `json:"largest_quoted_notional_usd,omitempty"`
	WorstExecutionShortfallPct      float64             `json:"worst_execution_shortfall_pct,omitempty"`
	WorstReferencePriceDropPct      float64             `json:"worst_reference_price_drop_pct,omitempty"`
	WorstJupiterPriceImpactPct      float64             `json:"worst_jupiter_price_impact_pct,omitempty"`
	MaxCanonicalReserveReferencePct float64             `json:"max_canonical_reserve_reference_pct,omitempty"`
	MaxQuoteContextSlot             uint64              `json:"max_quote_context_slot,omitempty"`
	MaxObservationSlotSpread        uint64              `json:"max_observation_slot_spread,omitempty"`
	RouteAttributedTierCount        int                 `json:"route_attributed_tier_count"`
	CanonicalPoolMatchedTierCount   int                 `json:"canonical_pool_matched_tier_count"`
	CanonicalPoolObservedInAnyRoute bool                `json:"canonical_pool_observed_in_any_route"`
	RouteAttributionStatus          string              `json:"route_attribution_status"`
	LPContext                       ExitImpactLPContext `json:"lp_context"`
	Tiers                           []ExitImpactTier    `json:"tiers"`
	Limitations                     []string            `json:"limitations"`
}

// ExitLiquiditySimulation estimates how much $1k/$10k/$100k sells would return
// through Jupiter's read-only quote endpoint. It never calls swap endpoints.
type ExitLiquiditySimulation struct {
	Available          bool                 `json:"available"`
	Status             string               `json:"status"`
	Provider           string               `json:"provider"`
	Mint               string               `json:"mint"`
	OutputMint         string               `json:"output_mint"`
	ReferencePriceUSD  float64              `json:"reference_price_usd,omitempty"`
	ReferencePriceFrom string               `json:"reference_price_source,omitempty"`
	TokenDecimals      int                  `json:"token_decimals,omitempty"`
	QuoteOnly          bool                 `json:"quote_only"`
	Tiers              []ExitLiquidityTier  `json:"tiers"`
	ImpactV2           ExitImpactAssessment `json:"impact_v2"`
	ObservedAt         time.Time            `json:"observed_at"`
	Limitations        []string             `json:"limitations"`
}
