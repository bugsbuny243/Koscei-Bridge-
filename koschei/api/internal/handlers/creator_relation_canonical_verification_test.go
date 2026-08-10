package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyCanonicalCreatorRelationRequiresSignerMintAndLaunchSemantics(t *testing.T) {
	const mint = "MintCanonical111"
	const creator = "CreatorCanonical111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var request struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Method != "getTransaction" {
			http.Error(w, "unexpected method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"slot":555123,"blockTime":1783364366,"transaction":{"message":{"accountKeys":[{"pubkey":"CreatorCanonical111","signer":true,"writable":true},{"pubkey":"MintCanonical111","signer":false,"writable":true}],"instructions":[{"program":"spl-token-2022","parsed":{"type":"initializeMint2","info":{"mint":"MintCanonical111"}}}]}},"meta":{"err":null,"preTokenBalances":[],"postTokenBalances":[{"mint":"MintCanonical111","owner":"CreatorCanonical111"}],"logMessages":["Program log: Instruction: Create","Program log: Instruction: InitializeMint2"]}}}`))
	}))
	defer server.Close()

	t.Setenv("SOLANA_RPC_URL", server.URL)
	t.Setenv("ALCHEMY_API_KEY", "legacy-key-must-not-win")
	h := &Handler{}
	got := h.verifyCanonicalCreatorRelation(t.Context(), mint, "solana-mainnet", creator, "Signature111")
	if !got.Verified || got.Status != "verified_canonical_create_transaction" {
		t.Fatalf("expected canonical verification, got %#v", got)
	}
	if got.Slot != 555123 || !got.CreatorSigner || !got.MintReferenced || !got.LaunchLike {
		t.Fatalf("canonical proof fields missing: %#v", got)
	}

	upgraded := applyCanonicalCreatorVerification(map[string]any{
		"creator_wallet": creator,
		"source":         "helius_das_and_rpc",
	}, got)
	if upgraded["creator_relation_verified"] != true || upgraded["slot"] != int64(555123) {
		t.Fatalf("source context was not upgraded: %#v", upgraded)
	}
	if upgraded["source"] != "solana_rpc_create_transaction" {
		t.Fatalf("verified provenance must become canonical Solana RPC, got %#v", upgraded["source"])
	}
}

func TestVerifyCanonicalCreatorRelationRejectsNonSigner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"slot":99,"blockTime":1783364366,"transaction":{"message":{"accountKeys":[{"pubkey":"CreatorNoSign","signer":false,"writable":true},{"pubkey":"MintNoSign","signer":false,"writable":true}],"instructions":[{"parsed":{"type":"initializeMint2","info":{"mint":"MintNoSign"}}}]}},"meta":{"err":null,"logMessages":["Program log: Instruction: Create"]}}}`))
	}))
	defer server.Close()
	t.Setenv("SOLANA_RPC_URL", server.URL)
	t.Setenv("ALCHEMY_API_KEY", "")

	got := (&Handler{}).verifyCanonicalCreatorRelation(t.Context(), "MintNoSign", "solana-mainnet", "CreatorNoSign", "SigNoSign")
	if got.Verified || got.Status != "creator_not_signer" {
		t.Fatalf("non-signer must not be upgraded: %#v", got)
	}
}

func TestVerifyCanonicalCreatorRelationRejectsWrongMint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"slot":100,"blockTime":1783364366,"transaction":{"message":{"accountKeys":[{"pubkey":"CreatorWrongMint","signer":true,"writable":true},{"pubkey":"DifferentMint","signer":false,"writable":true}],"instructions":[{"parsed":{"type":"initializeMint2","info":{"mint":"DifferentMint"}}}]}},"meta":{"err":null,"logMessages":["Program log: Instruction: Create"]}}}`))
	}))
	defer server.Close()
	t.Setenv("SOLANA_RPC_URL", server.URL)
	t.Setenv("ALCHEMY_API_KEY", "")

	got := (&Handler{}).verifyCanonicalCreatorRelation(t.Context(), "ExpectedMint", "solana-mainnet", "CreatorWrongMint", "SigWrongMint")
	if got.Verified || got.Status != "mint_not_referenced" {
		t.Fatalf("wrong mint must not be upgraded: %#v", got)
	}
}
