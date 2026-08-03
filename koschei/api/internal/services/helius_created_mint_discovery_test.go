package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
