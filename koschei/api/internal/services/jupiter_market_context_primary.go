package services

import "encoding/json"

const (
	JupiterPrimaryPriceProvider    = "jupiter"
	DexScreenerFallbackProvider   = "dexscreener_fallback"
	DexScreenerDiscoveryProvider  = "dexscreener"
	MarketProviderPolicyV1        = "jupiter_price_execution_primary_dexscreener_pair_discovery_fallback"
)

type PrimaryMarketPrice struct {
	Available             bool    `json:"available"`
	PriceUSD              float64 `json:"price_usd,omitempty"`
	Provider              string  `json:"provider"`
	FallbackUsed          bool    `json:"fallback_used"`
	PairDiscoveryProvider string  `json:"pair_discovery_provider"`
	Policy                string  `json:"policy"`
}

// ResolvePrimaryMarketPrice selects the customer-facing reference price without
// mutating ARVIS evidence or verdict semantics. Jupiter is preferred when its
// trusted read-only price evidence is available; DexScreener is retained only
// as an explicitly labelled price fallback and pair-discovery source.
func ResolvePrimaryMarketPrice(context JupiterMarketContext) PrimaryMarketPrice {
	out := PrimaryMarketPrice{
		Provider:              "unavailable",
		PairDiscoveryProvider: DexScreenerDiscoveryProvider,
		Policy:                MarketProviderPolicyV1,
	}
	if context.PriceAvailable && context.PriceUSD > 0 {
		out.Available = true
		out.PriceUSD = context.PriceUSD
		out.Provider = JupiterPrimaryPriceProvider
		return out
	}
	if context.DexScreenerPriceUSD > 0 {
		out.Available = true
		out.PriceUSD = context.DexScreenerPriceUSD
		out.Provider = DexScreenerFallbackProvider
		out.FallbackUsed = true
	}
	return out
}

// MarshalJSON adds provider-priority provenance to the existing Jupiter market
// context contract. Existing fields remain unchanged for backward compatibility.
// This is a projection only: provider priority cannot issue or change a verdict.
func (context JupiterMarketContext) MarshalJSON() ([]byte, error) {
	type alias JupiterMarketContext
	return json.Marshal(struct {
		alias
		PrimaryMarketPrice PrimaryMarketPrice `json:"primary_market_price"`
	}{
		alias:              alias(context),
		PrimaryMarketPrice: ResolvePrimaryMarketPrice(context),
	})
}
