package services

import "time"

// ExitLiquidityTier is one read-only Jupiter ExactIn quote. It is an estimate,
// not a guaranteed liquidation price and never creates a swap transaction.
type ExitLiquidityTier struct {
	RequestedNotionalUSD    float64   `json:"requested_notional_usd"`
	Available               bool      `json:"available"`
	Status                  string    `json:"status"`
	InputTokenAmount        float64   `json:"input_token_amount,omitempty"`
	InputAmountRaw          string    `json:"input_amount_raw,omitempty"`
	OutputAmountRaw         string    `json:"output_amount_raw,omitempty"`
	EstimatedProceedsUSD    float64   `json:"estimated_proceeds_usd,omitempty"`
	ExecutionShortfallUSD   float64   `json:"execution_shortfall_usd,omitempty"`
	ExecutionShortfallPct   float64   `json:"execution_shortfall_pct,omitempty"`
	ProceedsToNotionalPct   float64   `json:"proceeds_to_notional_pct,omitempty"`
	EffectiveExecutionPrice float64   `json:"effective_execution_price_usd,omitempty"`
	ReferencePriceDropPct   float64   `json:"reference_price_drop_pct,omitempty"`
	JupiterPriceImpactPct   float64   `json:"jupiter_price_impact_pct,omitempty"`
	QuoteContextSlot        uint64    `json:"quote_context_slot,omitempty"`
	RouteLabels             []string  `json:"route_labels"`
	ObservedAt              time.Time `json:"observed_at,omitempty"`
	Limitations             []string  `json:"limitations"`
}

// ExitLiquiditySimulation estimates how much $1k/$10k/$100k sells would return
// through Jupiter's read-only quote endpoint. It never calls swap endpoints.
type ExitLiquiditySimulation struct {
	Available          bool                `json:"available"`
	Status             string              `json:"status"`
	Provider           string              `json:"provider"`
	Mint               string              `json:"mint"`
	OutputMint         string              `json:"output_mint"`
	ReferencePriceUSD  float64             `json:"reference_price_usd,omitempty"`
	ReferencePriceFrom string              `json:"reference_price_source,omitempty"`
	TokenDecimals      int                 `json:"token_decimals,omitempty"`
	QuoteOnly          bool                `json:"quote_only"`
	Tiers              []ExitLiquidityTier `json:"tiers"`
	ObservedAt         time.Time           `json:"observed_at"`
	Limitations        []string            `json:"limitations"`
}
