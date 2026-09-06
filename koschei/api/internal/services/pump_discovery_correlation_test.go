package services

import "testing"

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
