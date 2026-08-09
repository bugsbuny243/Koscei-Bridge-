package web3

import (
	"context"
	"encoding/json"
	"testing"
)

func clearEvidenceCourtProviderEnv(t *testing.T) {
	t.Helper()
	t.Setenv("KOSCHEI_EVIDENCE_COURT_RPC_URLS", "")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ALCHEMY_RPC_URL", "")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_HELIUS_RPC_URL", "")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_QUICKNODE_RPC_URL", "")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "")
	 t.Setenv("ALCHEMY_API_KEY", "")
}

func TestRequiredCanonicalEvidenceCourtForcesCollectionPolicyWhenGlobalFlagOff(t *testing.T) {
	clearEvidenceCourtProviderEnv(t)
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "false")
	t.Setenv("SOLANA_RPC_URL", "https://primary-rpc.example")
	rpc := &SolanaRPC{}
	canonicalize := func(json.RawMessage) (string, uint64, bool, error) {
		return "unused", 0, false, nil
	}
	result := rpc.EvidenceCourtWithCanonicalizerExcludingRequired(
		context.Background(),
		"solana-mainnet",
		"getMultipleAccounts",
		[]any{[]string{"AddrA"}, map[string]any{"encoding": "base64", "commitment": "processed"}},
		"https://primary-rpc.example",
		2,
		canonicalize,
	)
	if !result.Enabled || result.Status != "insufficient" || result.Required != 2 || result.Requested != 0 {
		t.Fatalf("result=%#v", result)
	}
}

func TestOptionalCanonicalEvidenceCourtStillRespectsGlobalDisable(t *testing.T) {
	clearEvidenceCourtProviderEnv(t)
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "false")
	t.Setenv("SOLANA_RPC_URL", "https://primary-rpc.example")
	rpc := &SolanaRPC{}
	result := rpc.EvidenceCourtWithCanonicalizerExcluding(
		context.Background(),
		"solana-mainnet",
		"getMultipleAccounts",
		[]any{},
		"https://primary-rpc.example",
		func(json.RawMessage) (string, uint64, bool, error) { return "unused", 0, false, nil },
	)
	if result.Enabled || result.Status != "disabled" {
		t.Fatalf("result=%#v", result)
	}
}
