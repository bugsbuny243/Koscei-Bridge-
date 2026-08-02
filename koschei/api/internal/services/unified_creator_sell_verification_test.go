package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyCreatorSellTransactionsRequiresSignerBalanceDecreaseAndSellMarker(t *testing.T) {
	resetSolanaRPCCachesForTest()
	creator := "Creator1111111111111111111111111111111111"
	mint := "Mint11111111111111111111111111111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var request struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.Method != "getTransaction" {
			t.Fatalf("unexpected method %s", request.Method)
		}
		result := map[string]any{
			"meta": map[string]any{
				"err": nil,
				"preTokenBalances": []any{map[string]any{
					"owner": creator, "mint": mint,
					"uiTokenAmount": map[string]any{"amount": "1000"},
				}},
				"postTokenBalances": []any{map[string]any{
					"owner": creator, "mint": mint,
					"uiTokenAmount": map[string]any{"amount": "400"},
				}},
				"innerInstructions": []any{},
				"logMessages":       []any{"Program log: Instruction: Sell"},
			},
			"transaction": map[string]any{"message": map[string]any{
				"accountKeys": []any{map[string]any{"pubkey": creator, "signer": true}},
				"instructions": []any{map[string]any{
					"program": "pump", "parsed": map[string]any{"type": "sell", "info": map[string]any{}},
				}},
			}},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	defer server.Close()

	verification := VerifyCreatorSellTransactions(context.Background(), server.URL, CreatorSellAcceleration{
		Mint: mint, CreatorWallet: creator, Signatures: []string{"sell-signature"},
	})
	if verification.TransactionsParsed != 1 || len(verification.VerifiedSignatures) != 1 {
		t.Fatalf("verification=%#v", verification)
	}
	if verification.VerifiedSignatures[0] != "sell-signature" {
		t.Fatalf("signature=%v", verification.VerifiedSignatures)
	}
}
