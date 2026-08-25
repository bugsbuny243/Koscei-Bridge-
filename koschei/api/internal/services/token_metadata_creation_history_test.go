package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchBoundedMintCreationObservationPreservesExactCreateEvidence(t *testing.T) {
	const mint = "MintBounded111"
	const creator = "CreatorBounded111"
	const createSignature = "CreateBoundedSig111"

	t.Setenv("SOLANA_RPC_BATCH_ENABLED", "false")
	t.Setenv("TOKEN_METADATA_CREATION_SIGNATURE_LIMIT", "100")
	t.Setenv("TOKEN_METADATA_CREATION_TRANSACTION_LIMIT", "16")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch payload.Method {
		case "getSignaturesForAddress":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": []any{
					map[string]any{"signature": "NewerSig111", "slot": 700, "err": nil, "blockTime": 1700000700},
					map[string]any{"signature": "MiddleSig111", "slot": 600, "err": nil, "blockTime": 1700000600},
					map[string]any{"signature": createSignature, "slot": 500, "err": nil, "blockTime": 1700000500},
				},
			})
		case "getTransaction":
			var signature string
			if len(payload.Params) > 0 {
				_ = json.Unmarshal(payload.Params[0], &signature)
			}
			result := map[string]any{
				"slot":      float64(700),
				"blockTime": float64(1700000700),
				"transaction": map[string]any{
					"signatures": []any{signature},
					"message": map[string]any{
						"accountKeys":  []any{map[string]any{"pubkey": "OtherSigner111", "signer": true}},
						"instructions": []any{},
					},
				},
				"meta": map[string]any{"err": nil},
			}
			if signature == createSignature {
				result = map[string]any{
					"slot":      float64(500),
					"blockTime": float64(1700000500),
					"transaction": map[string]any{
						"signatures": []any{createSignature},
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
					"meta": map[string]any{"err": nil},
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		default:
			t.Fatalf("unexpected RPC method: %s", payload.Method)
		}
	}))
	defer server.Close()

	result, err := fetchBoundedMintCreationObservation(t.Context(), server.URL, mint)
	if err != nil {
		t.Fatal(err)
	}
	if result.HistoryBounded {
		t.Fatal("three-signature history should be complete inside the 100-signature window")
	}
	if result.SignaturesSeen != 3 || result.TransactionsRequested != 3 || result.TransactionsParsed != 3 {
		t.Fatalf("unexpected bounded coverage: %#v", result)
	}
	if result.Observation.Signature != createSignature || result.Observation.Creator != creator {
		t.Fatalf("exact creation evidence was not preserved: %#v", result.Observation)
	}
	if result.Observation.Slot != 500 || result.Observation.BlockTime != 1700000500 {
		t.Fatalf("unexpected creation provenance: %#v", result.Observation)
	}
}
