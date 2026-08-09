package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"koschei/api/internal/services"
)

type exitLiquidityRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn exitLiquidityRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func exitLiquidityTestAMMKey() string {
	return strings.Join([]string{"HXpGFJGC", "EEFdV31t", "DmjDBaJM", "EB1fKLiA", "oKoWr3Fn", "onid"}, "")
}

func TestCollectExitLiquiditySimulationQuotesFixedTiersReadOnly(t *testing.T) {
	ammKey := exitLiquidityTestAMMKey()
	t.Setenv("JUPITER_API_KEY", "unit-test")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/quote" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("x-api-key") != "" {
			http.Error(w, "Jupiter API key leaked to custom quote host", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("swapMode") != "ExactIn" {
			http.Error(w, "expected ExactIn", http.StatusBadRequest)
			return
		}
		amount := r.URL.Query().Get("amount")
		responses := map[string]struct{ out, impact string }{
			"500000000": {"990000000", "0.01"}, "5000000000": {"9000000000", "0.10"}, "50000000000": {"60000000000", "0.40"},
		}
		item, ok := responses[amount]
		if !ok {
			http.Error(w, "unexpected input amount", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"outAmount": item.out, "priceImpactPct": item.impact, "contextSlot": 99,
			"routePlan": []any{map[string]any{"swapInfo": map[string]any{"ammKey": ammKey, "label": "Raydium"}, "percent": 100}},
		})
	}))
	defer server.Close()
	t.Setenv("JUPITER_QUOTE_URL", server.URL+"/quote")
	rpc := func(_ context.Context, _, method string, _ any, out any) error {
		if method != "getTokenSupply" { t.Fatalf("unexpected RPC method %s", method) }
		response := out.(*rpcTokenSupplyResponse); response.Value.Amount = "1000000000000"; response.Value.Decimals = 6; return nil
	}
	result := collectExitLiquiditySimulation(context.Background(), rpc, server.Client(), "solana-mainnet", "Mint111", services.TokenMarketSnapshot{PriceUSD: 2}, services.JupiterMarketContext{})
	if !result.Available || result.Status != "complete" || len(result.Tiers) != 3 { t.Fatalf("unexpected result: %+v", result) }
	if result.Tiers[0].EstimatedProceedsUSD != 990 || result.Tiers[0].ReferencePriceDropPct != 1 { t.Fatalf("unexpected $1k tier: %+v", result.Tiers[0]) }
	if result.Tiers[1].ExecutionShortfallPct != 10 || result.Tiers[2].JupiterPriceImpactPct != 40 { t.Fatalf("unexpected larger tiers: %+v %+v", result.Tiers[1], result.Tiers[2]) }
	if len(result.Tiers[0].RoutePlan) != 1 || result.Tiers[0].RoutePlan[0].AMMKey != ammKey || result.Tiers[0].RoutePlan[0].Label != "Raydium" || result.Tiers[0].RoutePlan[0].Percent != 100 { t.Fatalf("route identity not captured: %+v", result.Tiers[0].RoutePlan) }
	if !result.QuoteOnly { t.Fatal("exit simulation must remain quote-only") }
}

func TestRequestExitLiquidityQuoteSendsAPIKeyOnlyToOfficialJupiterHost(t *testing.T) {
	t.Setenv("JUPITER_API_KEY", "unit-test")
	client := &http.Client{Transport: exitLiquidityRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Hostname() != "api.jup.ag" { t.Fatalf("host=%q", request.URL.Hostname()) }
		if request.Header.Get("x-api-key") != "unit-test" { t.Fatal("trusted Jupiter API key missing") }
		body := `{"outAmount":"1000000","priceImpactPct":"0","contextSlot":10,"routePlan":[]}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})}
	quote, err := requestExitLiquidityQuote(context.Background(), client, "https://api.jup.ag/swap/v1/quote?inputMint=a")
	if err != nil { t.Fatal(err) }
	if quote.OutAmount != "1000000" || quote.ContextSlot != 10 { t.Fatalf("unexpected quote: %#v", quote) }
}

func TestCollectExitLiquiditySimulationReportsPartialRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		amount, _ := strconv.ParseUint(r.URL.Query().Get("amount"), 10, 64)
		if amount > 1_000_000_000 { http.Error(w, "no route", http.StatusBadRequest); return }
		_ = json.NewEncoder(w).Encode(map[string]any{"outAmount": "950000000", "priceImpactPct": "0.05", "routePlan": []any{}})
	}))
	defer server.Close(); t.Setenv("JUPITER_QUOTE_URL", server.URL+"/quote")
	rpc := func(_ context.Context, _, _ string, _ any, out any) error { response := out.(*rpcTokenSupplyResponse); response.Value.Amount = "1000000000000"; response.Value.Decimals = 6; return nil }
	result := collectExitLiquiditySimulation(context.Background(), rpc, server.Client(), "solana-mainnet", "Mint111", services.TokenMarketSnapshot{PriceUSD: 2}, services.JupiterMarketContext{})
	if result.Status != "partial" || !result.Tiers[0].Available || result.Tiers[1].Available || result.Tiers[2].Available { t.Fatalf("unexpected partial result: %+v", result) }
}

func TestValidatedReadOnlyQuoteEndpointRejectsSwapPath(t *testing.T) {
	endpoint, _ := url.Parse("https://api.jup.ag/swap/v1/swap")
	if _, err := validatedReadOnlyQuoteEndpoint(endpoint.String()); err == nil { t.Fatal("swap endpoint must be rejected") }
}
