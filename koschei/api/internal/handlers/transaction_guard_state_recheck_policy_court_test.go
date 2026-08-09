package handlers

import (
	"context"
	"testing"
)

func TestStateRecheckSignedRequirementForcesCourtWhenGlobalDisabled(t *testing.T) {
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "false")
	t.Setenv("SOLANA_RPC_URL", "https://primary-rpc.example")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_RPC_URLS", "")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ALCHEMY_RPC_URL", "")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_HELIUS_RPC_URL", "")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_QUICKNODE_RPC_URL", "")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "")
	t.Setenv("ALCHEMY_API_KEY", "")

	court := collectTransactionGuardStateRecheckEvidenceCourtWithRequirement(
		context.Background(),
		"solana-mainnet",
		[]string{"AddrA"},
		transactionGuardStateRecheckCourtRequirement{Required: true, RequiredWitnesses: 2, SignedPolicy: true},
	)
	if !court.Enabled || court.Status != "insufficient" || court.Required != 2 || court.Requested >= court.Required || court.Available != 0 {
		t.Fatalf("court=%#v", court)
	}
	for _, witness := range court.Witnesses {
		if witness.Status != "not_queried" {
			t.Fatalf("insufficient provider set unexpectedly queried a witness: %#v", court.Witnesses)
		}
	}
}

func TestStateRecheckOptionalRequirementPreservesGlobalDisable(t *testing.T) {
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "false")
	t.Setenv("SOLANA_RPC_URL", "https://primary-rpc.example")
	court := collectTransactionGuardStateRecheckEvidenceCourtWithRequirement(
		context.Background(),
		"solana-mainnet",
		[]string{"AddrA"},
		transactionGuardStateRecheckCourtRequirement{},
	)
	if court.Enabled || court.Status != "disabled" {
		t.Fatalf("court=%#v", court)
	}
}