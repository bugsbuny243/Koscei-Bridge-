package services

import (
	"encoding/json"
	"testing"
)

func TestResolvePrimaryMarketPricePrefersJupiter(t *testing.T) {
	ctx := JupiterMarketContext{PriceAvailable: true, PriceUSD: 1.25, DexScreenerPriceUSD: 1.10}
	got := ResolvePrimaryMarketPrice(ctx)
	if !got.Available || got.PriceUSD != 1.25 || got.Provider != JupiterPrimaryPriceProvider || got.FallbackUsed {
		t.Fatalf("unexpected primary price: %#v", got)
	}
	if got.PairDiscoveryProvider != DexScreenerDiscoveryProvider {
		t.Fatalf("pair discovery provider=%q", got.PairDiscoveryProvider)
	}
}

func TestResolvePrimaryMarketPriceFallsBackWithoutPretendingJupiterSucceeded(t *testing.T) {
	ctx := JupiterMarketContext{PriceAvailable: false, DexScreenerPriceUSD: 0.91}
	got := ResolvePrimaryMarketPrice(ctx)
	if !got.Available || got.PriceUSD != 0.91 || got.Provider != DexScreenerFallbackProvider || !got.FallbackUsed {
		t.Fatalf("unexpected fallback price: %#v", got)
	}
}

func TestResolvePrimaryMarketPriceUnavailableIsNotSafeOrSynthetic(t *testing.T) {
	got := ResolvePrimaryMarketPrice(JupiterMarketContext{})
	if got.Available || got.PriceUSD != 0 || got.Provider != "unavailable" || got.FallbackUsed {
		t.Fatalf("unexpected unavailable price: %#v", got)
	}
}

func TestJupiterMarketContextJSONIncludesPrimaryProviderPolicy(t *testing.T) {
	raw, err := json.Marshal(JupiterMarketContext{PriceAvailable: true, PriceUSD: 2.5, DexScreenerPriceUSD: 2.0})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	primary, ok := decoded["primary_market_price"].(map[string]any)
	if !ok {
		t.Fatalf("primary_market_price missing: %s", string(raw))
	}
	if primary["provider"] != JupiterPrimaryPriceProvider {
		t.Fatalf("provider=%v", primary["provider"])
	}
	if primary["pair_discovery_provider"] != DexScreenerDiscoveryProvider {
		t.Fatalf("pair_discovery_provider=%v", primary["pair_discovery_provider"])
	}
	if primary["policy"] != MarketProviderPolicyV1 {
		t.Fatalf("policy=%v", primary["policy"])
	}
}
