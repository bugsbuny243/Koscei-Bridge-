package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func jupiterV2AdapterTestAMMKey() string {
	return strings.Join([]string{"HXpGFJGC", "EEFdV31t", "DmjDBaJM", "EB1fKLiA", "oKoWr3Fn", "onid"}, "")
}

func TestResolveExitLiquidityQuoteProviderDefaultsToSwapV2(t *testing.T) {
	t.Setenv("JUPITER_QUOTE_URL", "")
	t.Setenv("JUPITER_ORDER_URL", "")
	t.Setenv("JUPITER_API_KEY", "unit-test")
	provider, err := resolveExitLiquidityQuoteProvider()
	if err != nil {
		t.Fatal(err)
	}
	if provider.API != "swap_v2_order" {
		t.Fatalf("api=%q want swap_v2_order", provider.API)
	}
	if provider.Endpoint == nil || provider.Endpoint.String() != defaultJupiterOrderURL {
		t.Fatalf("endpoint=%v want %s", provider.Endpoint, defaultJupiterOrderURL)
	}
}

func TestResolveExitLiquidityQuoteProviderHonorsExplicitLegacyOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	t.Setenv("JUPITER_QUOTE_URL", server.URL+"/quote")
	t.Setenv("JUPITER_ORDER_URL", "")
	t.Setenv("JUPITER_API_KEY", "")
	provider, err := resolveExitLiquidityQuoteProvider()
	if err != nil {
		t.Fatal(err)
	}
	if provider.API != "metis_v1_quote" {
		t.Fatalf("api=%q want metis_v1_quote", provider.API)
	}
	if provider.Endpoint == nil || provider.Endpoint.Path != "/quote" {
		t.Fatalf("endpoint=%v", provider.Endpoint)
	}
}

func TestSwapV2ProviderQuoteIsStrictlyQuoteOnly(t *testing.T) {
	ammKey := jupiterV2AdapterTestAMMKey()
	t.Setenv("JUPITER_QUOTE_URL", "")
	t.Setenv("JUPITER_API_KEY", "unit-test")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/order" {
			http.Error(w, "unexpected route", http.StatusBadRequest)
			return
		}
		query := r.URL.Query()
		if query.Get("inputMint") != "InputMint" || query.Get("outputMint") != "OutputMint" || query.Get("amount") != "12345" || query.Get("swapMode") != "ExactIn" {
			http.Error(w, "missing required quote inputs", http.StatusBadRequest)
			return
		}
		for _, forbidden := range []string{"taker", "slippageBps", "restrictIntermediateTokens"} {
			if query.Get(forbidden) != "" {
				http.Error(w, "quote-only V2 request included "+forbidden, http.StatusBadRequest)
				return
			}
		if r.Header.Get("x-api-key") != "" {
			http.Error(w, "Jupiter API key leaked to custom order host", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"outAmount":   "990000000",
			"priceImpact": -0.25,
			"router":      "iris",
			"mode":        "ultra",
			"transaction": nil,
			"routePlan": []any{map[string]any{
				"swapInfo": map[string]any{"ammKey": ammKey, "label": "Meteora"},
				"percent": 100,
				"bps":     10000,
				"usdValue": 990.0,
			}},
		})
	}))
	defer server.Close()
	t.Setenv("JUPITER_ORDER_URL", server.URL+"/order")

	provider, err := resolveExitLiquidityQuoteProvider()
	if err != nil {
		t.Fatal(err)
	}
	quote, err := provider.quote(context.Background(), server.Client(), "InputMint", "OutputMint", "12345")
	if err != nil {
		t.Fatal(err)
	}
	if quote.OutAmount != "990000000" || quote.AdverseImpactPct != 0.25 || quote.Router != "iris" || quote.Mode != "ultra" {
		t.Fatalf("unexpected quote: %#v", quote)
	}
	if len(quote.RoutePlan) != 1 {
		t.Fatalf("route plan=%#v", quote.RoutePlan)
	}
	step := quote.RoutePlan[0]
	if step.AMMKey != ammKey || step.Label != "Meteora" || step.Percent != 100 || step.BPS != 10000 || step.USDValue != 990 {
		t.Fatalf("unexpected route step: %#v", step)
	}
}

func TestSwapV2QuoteRejectsUnexpectedTransaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"outAmount": "1",
			"transaction": "unexpected-executable-transaction",
			"routePlan": []any{},
		})
	}))
	defer server.Close()
	quoteURL := server.URL + "/order?inputMint=a&outputMint=b&amount=1&swapMode=ExactIn"
	if _, err := requestJupiterV2QuoteOnlyOrder(context.Background(), server.Client(), quoteURL); err == nil {
		t.Fatal("quote-only adapter accepted an executable transaction")
	}
}

func TestSwapV2PositivePriceImpactIsNotTreatedAsAdverse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"outAmount": "1",
			"priceImpact": 0.3,
			"transaction": nil,
			"routePlan": []any{},
		})
	}))
	defer server.Close()
	quoteURL := server.URL + "/order?inputMint=a&outputMint=b&amount=1&swapMode=ExactIn"
	quote, err := requestJupiterV2QuoteOnlyOrder(context.Background(), server.Client(), quoteURL)
	if err != nil {
		t.Fatal(err)
	}
	if quote.AdverseImpactPct != 0 {
		t.Fatalf("positive price impact was treated as adverse: %#v", quote)
	}
}

func TestSwapV2DeprecatedPriceImpactPctFallbackUsesLegacyRatioUnits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"outAmount": "1",
			"priceImpact": 0,
			"priceImpactPct": "0.0125",
			"transaction": nil,
			"routePlan": []any{},
		})
	}))
	defer server.Close()
	quoteURL := server.URL + "/order?inputMint=a&outputMint=b&amount=1&swapMode=ExactIn"
	quote, err := requestJupiterV2QuoteOnlyOrder(context.Background(), server.Client(), quoteURL)
	if err != nil {
		t.Fatal(err)
	}
	if quote.AdverseImpactPct != 1.25 {
		t.Fatalf("deprecated ratio fallback=%v want 1.25", quote.AdverseImpactPct)
	}
}
