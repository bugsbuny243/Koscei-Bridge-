package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"koschei/api/internal/services"
)

func TestCollectTrustedJupiterMarketContextUsesTrustedPriceAndSwapV2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "" {
			http.Error(w, "Jupiter key leaked to custom host", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/price":
			if r.URL.Query().Get("ids") != "Mint111" {
				http.Error(w, "missing price mint", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Mint111": map[string]any{"usdPrice": 2.2, "blockId": 77},
			})
		case "/order":
			query := r.URL.Query()
			if query.Get("inputMint") != "Mint111" || query.Get("outputMint") != jupiterUSDCMint || query.Get("swapMode") != "ExactIn" {
				http.Error(w, "invalid order query", http.StatusBadRequest)
				return
			}
			if query.Get("taker") != "" || query.Get("slippageBps") != "" {
				http.Error(w, "market context must remain quote-only", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"outAmount":   "123000000",
				"priceImpact": -0.4,
				"router":      "iris",
				"mode":        "ultra",
				"transaction": nil,
				"routePlan": []any{map[string]any{
					"swapInfo": map[string]any{"ammKey": "11111111111111111111111111111111", "label": "System Test Route"},
					"percent":  100,
					"bps":      10000,
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Setenv("JUPITER_API_KEY", "unit-test")
	t.Setenv("JUPITER_PRICE_URL", server.URL+"/price")
	t.Setenv("JUPITER_QUOTE_URL", "")
	t.Setenv("JUPITER_ORDER_URL", server.URL+"/order")

	rpcNetwork := ""
	rpc := func(_ context.Context, network, method string, _ any, out any) error {
		rpcNetwork = network
		if method != "getTokenSupply" {
			t.Fatalf("unexpected method %s", method)
		}
		response := out.(*rpcTokenSupplyResponse)
		response.Value.Amount = "1000000000000"
		response.Value.Decimals = 6
		return nil
	}
	holder := services.HolderIntelligence{Available: true, CirculatingSupply: 1000, Top1Percentage: 10}
	market := services.TokenMarketSnapshot{PriceUSD: 2}
	result := collectTrustedJupiterMarketContext(context.Background(), rpc, server.Client(), "solana-mainnet", "Mint111", holder, market)

	if rpcNetwork != "solana-mainnet" {
		t.Fatalf("network=%q", rpcNetwork)
	}
	if !result.Available || result.Status != "complete" || !result.PriceAvailable || !result.SellImpactAvailable {
		t.Fatalf("unexpected context: %#v", result)
	}
	if result.PriceUSD != 2.2 || result.PriceBlockID != 77 || result.PriceDifferencePct != 10 {
		t.Fatalf("unexpected price evidence: %#v", result)
	}
	if result.SellQuoteAPI != "swap_v2_order" || result.SellQuoteRouter != "iris" || result.SellQuoteMode != "ultra" {
		t.Fatalf("unexpected quote transport: %#v", result)
	}
	if result.EstimatedPriceImpactPct != 0.4 || result.SellOutputAmountRaw != "123000000" {
		t.Fatalf("unexpected sell impact: %#v", result)
	}
	if len(result.RouteLabels) != 1 || result.RouteLabels[0] != "System Test Route" {
		t.Fatalf("route labels=%#v", result.RouteLabels)
	}
	if result.QuoteContextSlot != 0 {
		t.Fatalf("Swap V2 collector invented quote context slot: %d", result.QuoteContextSlot)
	}
}

func TestCollectTrustedJupiterMarketContextCanReturnPriceOnlyWhenOfficialQuoteKeyUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"Mint111": map[string]any{"usdPrice": 1.0}})
	}))
	defer server.Close()
	t.Setenv("JUPITER_PRICE_URL", server.URL+"/price")
	t.Setenv("JUPITER_QUOTE_URL", "")
	t.Setenv("JUPITER_ORDER_URL", "")
	t.Setenv("JUPITER_API_KEY", "")

	rpc := func(_ context.Context, _, _ string, _ any, out any) error {
		response := out.(*rpcTokenSupplyResponse)
		response.Value.Amount = "1000000"
		response.Value.Decimals = 6
		return nil
	}
	result := collectTrustedJupiterMarketContext(
		context.Background(), rpc, server.Client(), "solana-mainnet", "Mint111",
		services.HolderIntelligence{Available: true, CirculatingSupply: 100, Top1Percentage: 10},
		services.TokenMarketSnapshot{PriceUSD: 1},
	)
	if !result.PriceAvailable || result.SellImpactAvailable || result.Status != "price_only" {
		t.Fatalf("unexpected price-only context: %#v", result)
	}
	if len(result.Limitations) == 0 {
		t.Fatal("missing provider limitation")
	}
}
