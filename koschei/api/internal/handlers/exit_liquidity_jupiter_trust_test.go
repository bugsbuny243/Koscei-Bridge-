package handlers

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"koschei/api/internal/services"
)

func TestJupiterAPIKeyForQuoteEndpointRejectsLookalikeHost(t *testing.T) {
	t.Setenv("JUPITER_API_KEY", "unit-test")
	for _, endpoint := range []string{
		"https://api.jup.ag.evil.example/swap/v1/quote",
		"https://evil.example/quote",
		"http://localhost/quote",
	} {
		if got := jupiterAPIKeyForQuoteEndpoint(endpoint); got != "" {
			t.Fatalf("Jupiter API key leaked to %q", endpoint)
		}
	}
	if got := jupiterAPIKeyForQuoteEndpoint("https://api.jup.ag/swap/v1/quote"); got != "unit-test" {
		t.Fatalf("official Jupiter host did not receive configured key: %q", got)
	}
}

func TestCollectExitLiquiditySimulationFailsBeforeHTTPWhenOfficialJupiterKeyMissing(t *testing.T) {
	t.Setenv("JUPITER_API_KEY", "")
	t.Setenv("JUPITER_QUOTE_URL", "https://api.jup.ag/swap/v1/quote")

	var called atomic.Bool
	client := &http.Client{Transport: exitLiquidityRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		called.Store(true)
		t.Fatalf("official Jupiter HTTP request should not run without JUPITER_API_KEY")
		return nil, nil
	})}
	rpc := func(_ context.Context, _, method string, _ any, out any) error {
		if method != "getTokenSupply" {
			t.Fatalf("unexpected RPC method %s", method)
		}
		response := out.(*rpcTokenSupplyResponse)
		response.Value.Amount = "1000000000000"
		response.Value.Decimals = 6
		return nil
	}

	result := collectExitLiquiditySimulation(
		context.Background(), rpc, client, "solana-mainnet", "Mint111",
		services.TokenMarketSnapshot{PriceUSD: 2}, services.JupiterMarketContext{},
	)
	if called.Load() {
		t.Fatal("missing API key still reached official Jupiter HTTP transport")
	}
	if result.Available || result.Status != "jupiter_api_key_unavailable" {
		t.Fatalf("unexpected missing-key result: %#v", result)
	}
	if len(result.Limitations) == 0 {
		t.Fatal("missing-key result must explain the limitation")
	}
}
