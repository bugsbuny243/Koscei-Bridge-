package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFetchHeliusTokenMetadataDefaultAvoidsArchivalHistory(t *testing.T) {
	const mint = "MintDefault111"
	const creator = "CreatorDefault111"
	archivalCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch payload.Method {
		case "getAsset":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"result": map[string]any{
					"id": mint,
					"content": map[string]any{"metadata": map[string]any{
						"name": "Free First Token", "symbol": "FFT", "token_standard": "Fungible",
					}},
					"creators": []any{map[string]any{"address": creator, "verified": true, "share": 100}},
				},
			})
		case "getSignaturesForAddress":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1, "result": []any{},
			})
		case "getTransactionsForAddress":
			archivalCalls++
			t.Fatal("default token metadata must not call Helius getTransactionsForAddress")
		default:
			t.Fatalf("unexpected RPC method: %s", payload.Method)
		}
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
	t.Setenv("HELIUS_CREATED_MINT_ARCHIVAL_ENABLED", "")
	metadata := FetchHeliusTokenMetadata(t.Context(), server.URL, mint)
	if archivalCalls != 0 {
		t.Fatalf("default metadata made %d archival calls", archivalCalls)
	}
	if !metadata.Configured || !metadata.Available || metadata.Status != "complete" {
		t.Fatalf("unexpected metadata result: %#v", metadata)
	}
	if metadata.Creator != creator || metadata.CreateTransaction != "" {
		t.Fatalf("unexpected default creator evidence: %#v", metadata)
	}
	if metadata.CreationHistorySource != "solana_rpc_bounded_mint_history" || metadata.CreationHistoryBounded {
		t.Fatalf("unexpected bounded history provenance: %#v", metadata)
	}
	if !metadataLimitationsContain(metadata.Limitations, "No exact creation transaction was observed") {
		t.Fatalf("missing bounded-history limitation: %#v", metadata.Limitations)
	}
}

func TestFetchHeliusTokenMetadataCombinesDASAndCreationHistoryWhenArchivalEnabled(t *testing.T) {
	const mint = "Mint111"
	const creator = "Creator111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch payload.Method {
		case "getAsset":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"result": map[string]any{
					"id": mint,
					"content": map[string]any{"metadata": map[string]any{
						"name": "Koschei Test Token", "symbol": "KTT", "token_standard": "Fungible",
					}},
					"creators": []any{map[string]any{"address": creator, "verified": true, "share": 100}},
					"token_info": map[string]any{
						"symbol": "KTT", "mint_authority": creator, "freeze_authority": "Freeze111",
					},
					"mint_extensions": map[string]any{"metadata_pointer": map[string]any{"authority": creator}},
				},
			})
		case "getTransactionsForAddress":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"result": map[string]any{
					"paginationToken": "",
					"data": []any{map[string]any{
						"slot": float64(500), "blockTime": float64(1700000000),
						"transaction": map[string]any{
							"signatures": []any{"CreateSig111"},
							"message": map[string]any{
								"accountKeys": []any{
									map[string]any{"pubkey": creator, "signer": true},
									map[string]any{"pubkey": mint, "signer": true},
								},
								"instructions": []any{map[string]any{
									"programId": canonicalSPLTokenProgramID,
									"parsed": map[string]any{
										"type": "initializeMint2",
										"info": map[string]any{"mint": mint},
									},
								}},
							},
						},
					}},
				},
			})
		default:
			t.Fatalf("unexpected Helius method: %s", payload.Method)
		}
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
	metadata := FetchHeliusTokenMetadata(t.Context(), "", mint)
	if !metadata.Configured || !metadata.Available || metadata.Status != "complete" {
		t.Fatalf("unexpected metadata result: %#v", metadata)
	}
	if metadata.Provider != "helius_das_and_rpc" || metadata.Name != "Koschei Test Token" || metadata.Symbol != "KTT" {
		t.Fatalf("DAS metadata missing: %#v", metadata)
	}
	if metadata.Creator != creator || metadata.CreateTransaction != "CreateSig111" {
		t.Fatalf("creator history missing: %#v", metadata)
	}
	if metadata.CreationHistorySource != "helius_get_transactions_for_address" {
		t.Fatalf("unexpected archival provenance: %#v", metadata)
	}
	if metadata.MintAuthority != creator || metadata.FreezeAuthority != "Freeze111" {
		t.Fatalf("authority metadata missing: %#v", metadata)
	}
}

func TestExtractMintCreationObservationRequiresExactMintInstruction(t *testing.T) {
	tx := map[string]any{
		"slot": float64(10), "blockTime": float64(20),
		"transaction": map[string]any{
			"signatures": []any{"Sig111"},
			"message": map[string]any{
				"accountKeys": []any{map[string]any{"pubkey": "Creator111", "signer": true}},
				"instructions": []any{map[string]any{
					"programId": canonicalSPLTokenProgramID,
					"parsed": map[string]any{
						"type": "initializeMint2",
						"info": map[string]any{"mint": "OtherMint111"},
					},
				}},
			},
		},
	}
	if observation, ok := extractMintCreationObservation(tx, "ExpectedMint111"); ok {
		t.Fatalf("wrong mint produced creation observation: %#v", observation)
	}
}

func metadataLimitationsContain(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
