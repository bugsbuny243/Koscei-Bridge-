package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchHeliusCreatedMintDiscoveryDefaultsToBoundedStandardRPC(t *testing.T) {
	methods := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		methods = append(methods, payload.Method)
		w.Header().Set("Content-Type", "application/json")
		switch payload.Method {
		case "getSignaturesForAddress":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": []any{map[string]any{
					"signature": "SigMint111", "slot": 101, "err": nil, "blockTime": 1700000000,
				}},
			})
		case "getTransaction":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"slot": float64(101), "blockTime": float64(1700000000),
					"transaction": map[string]any{
						"signatures": []any{"SigMint111"},
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
			})
		case "getTransactionsForAddress":
			t.Fatalf("paid archival method must not be called by default")
		default:
			t.Fatalf("unexpected RPC method: %s", payload.Method)
		}
	}))
	defer server.Close()

	previousRPCClient := solanaRPCClient
	solanaRPCClient = server.Client()
	defer func() { solanaRPCClient = previousRPCClient }()

	t.Setenv("HELIUS_CREATED_MINT_ARCHIVAL_ENABLED", "")
	t.Setenv("HELIUS_API_KEY", "configured-but-not-a-trigger")
	t.Setenv("SOLANA_RPC_BATCH_ENABLED", "false")
	out := FetchHeliusCreatedMintDiscovery(t.Context(), server.URL, "Actor111")
	if !out.Configured || !out.Available {
		t.Fatalf("bounded standard RPC discovery should be available: %#v", out)
	}
	if out.Provider != boundedCreatedMintRPCProvider {
		t.Fatalf("expected bounded RPC provider, got %s", out.Provider)
	}
	if out.Status != "complete" {
		t.Fatalf("single exhausted signature window should be complete, got %s: %#v", out.Status, out)
	}
	if len(out.Candidates) != 1 || out.Candidates[0].Mint != "Mint111" {
		t.Fatalf("created mint not extracted from standard RPC: %#v", out.Candidates)
	}
	for _, method := range methods {
		if method == "getTransactionsForAddress" {
			t.Fatalf("default path used paid archival method")
		}
	}
}

func TestSelectCreatedMintRPCSignaturesSpreadsBoundedCoverage(t *testing.T) {
	rows := []SolanaSignatureInfo{
		{Signature: "s0"}, {Signature: "s1"}, {Signature: "s2"}, {Signature: "s3"},
		{Signature: "s4"}, {Signature: "s5"}, {Signature: "s6"}, {Signature: "s7"},
		{Signature: "s8"}, {Signature: "s9"},
	}
	got := selectCreatedMintRPCSignatures(rows, 4)
	want := []string{"s0", "s3", "s6", "s9"}
	if len(got) != len(want) {
		t.Fatalf("unexpected selection length: got %#v want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("unexpected bounded selection: got %#v want %#v", got, want)
		}
	}
}

func TestHeliusCreatedMintArchivalRequiresExplicitOptIn(t *testing.T) {
	for _, value := range []string{"true", "TRUE", "1", "yes", "on"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("HELIUS_CREATED_MINT_ARCHIVAL_ENABLED", value)
			if !heliusCreatedMintArchivalEnabled() {
				t.Fatalf("expected %q to enable archival created-mint discovery", value)
			}
		})
	}
	for _, value := range []string{"", "false", "0", "no", "off", "unexpected"} {
		t.Run("disabled_"+value, func(t *testing.T) {
			t.Setenv("HELIUS_CREATED_MINT_ARCHIVAL_ENABLED", value)
			if heliusCreatedMintArchivalEnabled() {
				t.Fatalf("expected %q to keep archival created-mint discovery disabled", value)
			}
		})
	}
}
