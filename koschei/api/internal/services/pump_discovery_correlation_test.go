package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPumpDiscoveryTransactionReferencesMintFromAccountKeys(t *testing.T) {
	mint := "MintDiscovery11111111111111111111111111111"
	tx := map[string]any{
		"transaction": map[string]any{
			"message": map[string]any{
				"accountKeys": []any{"Signer111", mint, defaultPumpProgramID},
			},
		},
	}
	if !pumpDiscoveryTransactionReferencesMint(tx, mint) {
		t.Fatal("expected mint reference from transaction account keys")
	}
}

func TestPumpDiscoveryTransactionReferencesMintFromTokenBalances(t *testing.T) {
	mint := "MintDiscovery22222222222222222222222222222"
	tx := map[string]any{
		"transaction": map[string]any{"message": map[string]any{"accountKeys": []any{"Signer222"}}},
		"meta": map[string]any{
			"postTokenBalances": []any{map[string]any{"mint": mint}},
		},
	}
	if !pumpDiscoveryTransactionReferencesMint(tx, mint) {
		t.Fatal("expected mint reference from token balances")
	}
}

func TestPumpDiscoveryTransactionDoesNotInventMintReference(t *testing.T) {
	tx := map[string]any{
		"transaction": map[string]any{
			"message": map[string]any{
				"accountKeys": []any{"Signer333", defaultPumpProgramID},
			},
		},
		"meta": map[string]any{
			"postTokenBalances": []any{map[string]any{"mint": "OtherMint"}},
		},
	}
	if pumpDiscoveryTransactionReferencesMint(tx, "RequestedMint") {
		t.Fatal("unrelated transaction was treated as mint-correlated")
	}
}

func TestCorrelatePumpPortalDiscoveryEventRequiresSignature(t *testing.T) {
	out := CorrelatePumpPortalDiscoveryEvent(context.Background(), "http://unused", "helius_rpc", "Mint", "", "new_token", 1)
	if out.Status != "signature_unavailable" {
		t.Fatalf("status=%q want signature_unavailable", out.Status)
	}
	if out.SemanticStatus != "source_reported_not_independently_decoded" {
		t.Fatalf("semantic status was strengthened without evidence: %q", out.SemanticStatus)
	}
}

func TestCorrelatePumpPortalDiscoveryEventMatchesExactBoundedEvidence(t *testing.T) {
	prepareSolanaRPCBatchTest(t)
	mint := "MintDiscovery44444444444444444444444444444"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requests []solanaRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		responses := make([]map[string]any, 0, len(requests))
		for _, request := range requests {
			responses = append(responses, map[string]any{
				"jsonrpc": "2.0",
				"id":      request.ID,
				"result": map[string]any{
					"slot": 444,
					"transaction": map[string]any{
						"message": map[string]any{
							"accountKeys": []any{"Signer444", mint, defaultPumpProgramID},
						},
					},
					"meta": map[string]any{},
				},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses)
	}))
	defer server.Close()

	out := CorrelatePumpPortalDiscoveryEvent(context.Background(), server.URL, "canonical_solana_rpc_fallback", mint, "sig-444", "new_token", 444)
	if out.Status != "signature_correlated" {
		t.Fatalf("status=%q reason=%q limitations=%v", out.Status, out.ReasonCode, out.Limitations)
	}
	if !out.Available || !out.MintReferenceObserved {
		t.Fatalf("expected available mint-correlated transaction: %+v", out)
	}
	if out.CanonicalSlot != 444 {
		t.Fatalf("canonical slot=%d want 444", out.CanonicalSlot)
	}
	if out.Program != "pump.fun" {
		t.Fatalf("program=%q want pump.fun", out.Program)
	}
	if out.SemanticStatus != "source_reported_not_independently_decoded" {
		t.Fatalf("correlation improperly promoted event semantics: %q", out.SemanticStatus)
	}
}

func TestCorrelatePumpPortalDiscoveryEventRejectsSlotMismatch(t *testing.T) {
	prepareSolanaRPCBatchTest(t)
	mint := "MintDiscovery55555555555555555555555555555"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requests []solanaRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		responses := make([]map[string]any, 0, len(requests))
		for _, request := range requests {
			responses = append(responses, map[string]any{
				"jsonrpc": "2.0",
				"id":      request.ID,
				"result": map[string]any{
					"slot": 556,
					"transaction": map[string]any{
						"message": map[string]any{"accountKeys": []any{mint, defaultPumpProgramID}},
					},
					"meta": map[string]any{},
				},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses)
	}))
	defer server.Close()

	out := CorrelatePumpPortalDiscoveryEvent(context.Background(), server.URL, "canonical_solana_rpc_fallback", mint, "sig-555", "migration", 555)
	if out.Status != "observed_mismatch" || out.ReasonCode != "slot_mismatch" {
		t.Fatalf("mismatched observation was accepted: %+v", out)
	}
	if out.SemanticStatus != "source_reported_not_independently_decoded" {
		t.Fatalf("mismatch changed semantic status: %q", out.SemanticStatus)
	}
}
