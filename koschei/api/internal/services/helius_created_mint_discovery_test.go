package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type heliusRewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (transport heliusRewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme = transport.target.Scheme
	clone.URL.Host = transport.target.Host
	return transport.base.RoundTrip(clone)
}

func TestFetchHeliusCreatedMintDiscoveryUsesCurrentHistoryRPC(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Method != "getTransactionsForAddress" {
			t.Fatalf("unexpected method: %s", payload.Method)
		}
		if len(payload.Params) != 2 || payload.Params[0] != "Actor111" {
			t.Fatalf("unexpected params: %#v", payload.Params)
		}
		options, _ := payload.Params[1].(map[string]any)
		if options["transactionDetails"] != "full" || options["encoding"] != "jsonParsed" {
			t.Fatalf("missing full jsonParsed options: %#v", options)
		}
		if options["limit"] != float64(100) {
			t.Fatalf("full getTransactionsForAddress page must stay within 100 records: %#v", options)
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"result": map[string]any{
					"paginationToken": "next-page",
					"data": []any{
						map[string]any{
							"slot": float64(100), "blockTime": float64(1700000000),
							"transaction": map[string]any{
								"signatures": []any{"Sig111"},
								"message": map[string]any{
									"accountKeys": []any{map[string]any{"pubkey": "Actor111", "signer": true}},
									"instructions": []any{map[string]any{
										"programId": canonicalSPLTokenProgramID,
										"parsed": map[string]any{
											"type": "initializeMint",
											"info": map[string]any{"mint": "Mint111"},
										},
									}},
								},
							},
						},
					},
				},
			})
			return
		}
		if options["paginationToken"] != "next-page" {
			t.Fatalf("pagination token not propagated: %#v", options)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"result":  map[string]any{"paginationToken": "", "data": []any{}},
		})
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	previousClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: heliusRewriteTransport{target: target, base: server.Client().Transport}}
	defer func() { http.DefaultClient = previousClient }()

	t.Setenv("HELIUS_API_KEY", "test-key")
	t.Setenv("HELIUS_CREATED_MINT_ARCHIVAL_ENABLED", "true")
	t.Setenv("HELIUS_CREATED_MINT_PAGE_DELAY_MS", "0")
	out := FetchHeliusCreatedMintDiscovery(t.Context(), "", "Actor111")
	if !out.Available || out.Status != "complete" || out.PagesFetched != 2 {
		t.Fatalf("unexpected discovery coverage: %#v", out)
	}
	if out.Provider != "helius_get_transactions_for_address" {
		t.Fatalf("unexpected provider: %s", out.Provider)
	}
	if len(out.Candidates) != 1 || out.Candidates[0].Mint != "Mint111" {
		t.Fatalf("created mint not extracted: %#v", out.Candidates)
	}
}

func TestFetchHeliusCreatedMintDiscoveryFallsBackWhenArchivalPlanRejects(t *testing.T) {
	archivalCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch payload.Method {
		case "getTransactionsForAddress":
			archivalCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"error":   map[string]any{"code": -32000, "message": "Developer plan required"},
			})
		case "getSignaturesForAddress":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": []any{map[string]any{
					"signature": "SigFallback", "slot": 101, "err": nil, "blockTime": 1700000000,
				}},
			})
		case "getTransaction":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": heliusFallbackCreatedMintTransaction(),
			})
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	previousDefaultClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: heliusRewriteTransport{target: target, base: server.Client().Transport}}
	defer func() { http.DefaultClient = previousDefaultClient }()
	previousRPCClient := solanaRPCClient
	solanaRPCClient = server.Client()
	defer func() { solanaRPCClient = previousRPCClient }()
	resetSolanaRPCCachesForTest()
	resetSolanaRPCBatchCircuitForTest()
	resetSolanaRPCBatchModeCacheForTest()

	t.Setenv("HELIUS_API_KEY", "test-key")
	t.Setenv("HELIUS_CREATED_MINT_ARCHIVAL_ENABLED", "true")
	t.Setenv("HELIUS_CREATED_MINT_PAGE_DELAY_MS", "0")
	t.Setenv("SOLANA_RPC_BATCH_ENABLED", "false")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")

	out := FetchHeliusCreatedMintDiscovery(t.Context(), server.URL, "Actor111")
	if archivalCalls != 1 {
		t.Fatalf("expected one archival attempt before fallback, got %d", archivalCalls)
	}
	if !out.Available || out.Provider != boundedCreatedMintRPCProvider {
		t.Fatalf("expected bounded standard RPC fallback, got %#v", out)
	}
	if len(out.Candidates) != 1 || out.Candidates[0].Mint != "MintFallback" {
		t.Fatalf("fallback created mint not extracted: %#v", out.Candidates)
	}
	limitations := strings.Join(out.Limitations, " ")
	if !strings.Contains(limitations, "bounded standard RPC fallback was used") || !strings.Contains(limitations, "Developer plan required") {
		t.Fatalf("fallback cause must remain explainable: %q", limitations)
	}
}

func heliusFallbackCreatedMintTransaction() map[string]any {
	return map[string]any{
		"slot":      float64(101),
		"blockTime": float64(1700000000),
		"transaction": map[string]any{
			"signatures": []any{"SigFallback"},
			"message": map[string]any{
				"accountKeys": []any{map[string]any{"pubkey": "Actor111", "signer": true}},
				"instructions": []any{map[string]any{
					"programId": canonicalSPLTokenProgramID,
					"parsed": map[string]any{
						"type": "initializeMint",
						"info": map[string]any{"mint": "MintFallback"},
					},
				}},
			},
		},
		"meta": map[string]any{"err": nil},
	}
}
