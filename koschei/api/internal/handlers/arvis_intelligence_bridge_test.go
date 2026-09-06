package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestArvisIntelligenceBridgeCarriesObservedSolanaTransactionEvidence(t *testing.T) {
	observedAt := time.Date(2026, 9, 6, 6, 0, 0, 0, time.UTC)
	investigation := buildArvisIntelligenceBridge(
		"62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump",
		"solana-mainnet",
		[]unifiedTransactionEvidence{{
			Signature: "sig-123",
			Slot:      12345,
			Trader:    "wallet-1",
			Direction: "sell",
			BlockTime: &observedAt,
			Source:    "helius",
		}},
		observedAt,
	)

	if len(investigation.Subjects) != 1 {
		t.Fatalf("expected one subject, got %d", len(investigation.Subjects))
	}
	if investigation.Subjects[0].ChainFamily != services.IntelligenceChainFamilySolana {
		t.Fatalf("expected solana subject, got %#v", investigation.Subjects[0])
	}
	if len(investigation.Evidence) != 1 {
		t.Fatalf("expected one evidence row, got %#v", investigation.Evidence)
	}
	evidence := investigation.Evidence[0]
	if evidence.TransactionHash != "sig-123" || evidence.BlockOrSlot != 12345 {
		t.Fatalf("transaction evidence was not preserved: %#v", evidence)
	}
	if evidence.Source != "helius" || evidence.Provenance != "existing_arvis_transaction_evidence" {
		t.Fatalf("evidence provenance missing: %#v", evidence)
	}
	if evidence.Status != services.IntelligenceEvidenceObserved {
		t.Fatalf("expected observed evidence, got %q", evidence.Status)
	}
	if investigation.Decision.Status != services.IntelligenceEvidenceUnverified || investigation.Decision.Action != "investigate" {
		t.Fatalf("observed transaction evidence must not manufacture a verdict: %#v", investigation.Decision)
	}
}

func TestArvisIntelligenceBridgeDoesNotInventEvidence(t *testing.T) {
	investigation := buildArvisIntelligenceBridge(
		"62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump",
		"solana-mainnet",
		[]unifiedTransactionEvidence{{Source: "helius"}},
		time.Now().UTC(),
	)
	if len(investigation.Evidence) != 0 {
		t.Fatalf("empty ARVIS transaction row must not become evidence: %#v", investigation.Evidence)
	}
}

func TestArvisIntelligenceBridgeDoesNotPretendEVMCollectorExists(t *testing.T) {
	investigation := buildArvisIntelligenceBridge(
		"0xe1e5f00a9b0255ca4df85b3130ee0f77d15acc2d",
		"ethereum-mainnet",
		[]unifiedTransactionEvidence{{Signature: "solana-shaped-row", Slot: 99, Source: "legacy"}},
		time.Now().UTC(),
	)
	if len(investigation.Evidence) != 0 {
		t.Fatalf("EVM subject must not inherit Solana ARVIS transaction rows: %#v", investigation.Evidence)
	}
	if len(investigation.Subjects) != 1 || investigation.Subjects[0].ChainFamily != services.IntelligenceChainFamilyEVM {
		t.Fatalf("expected syntactic EVM subject: %#v", investigation.Subjects)
	}
}
