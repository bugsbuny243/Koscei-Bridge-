package handlers

import (
	"testing"
	"time"
)

func TestCustomerTransactionEnvelopeExposesHistoricalMemoryAsContext(t *testing.T) {
	report := newTransactionInvestigationReport("sig111", "solana-mainnet")
	report.Status = "complete"
	report.EvidenceRefs = []string{"rpc:getTransaction"}
	history := intelligenceMemoryReadReceipt{
		Status:     "verified_history_available",
		Available:  true,
		Backend:    "google_drive",
		Kind:       "transaction_investigation",
		Network:    "solana-mainnet",
		CapturedAt: time.Unix(1_700_000_000, 0).UTC(),
		Payload:    map[string]any{"status": "previous"},
		Limitations: []string{
			"Historical Drive memory is contextual evidence only.",
		},
	}
	envelope := customerTransactionInvestigationEnvelope(report, radarTargetClassification{Type: radarTargetTransactionSignature}, false, history)
	got, ok := envelope["historical_memory"].(intelligenceMemoryReadReceipt)
	if !ok || !got.Available || got.Payload["status"] != "previous" {
		t.Fatalf("historical memory=%+v", envelope["historical_memory"])
	}
	policy, _ := envelope["evidence_policy"].(map[string]any)
	if policy["historical_memory_cannot_override_live_evidence"] != true {
		t.Fatalf("policy=%+v", policy)
	}
}

func TestHistoricalMemoryUnconfiguredIsExplicitGap(t *testing.T) {
	t.Setenv("GOOGLE_DRIVE_ARCHIVE_FOLDER_ID", "folder-1")
	t.Setenv("GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON", "")
	receipt := loadLatestIntelligenceMemory(t.Context(), "wallet_investigation", "solana-mainnet", "wallet111")
	if receipt.Status != "drive_unavailable" || receipt.ConfigurationStatus != "credential_missing" {
		t.Fatalf("receipt=%+v", receipt)
	}
	if receipt.Available {
		t.Fatal("unconfigured Drive must not report historical memory as available")
	}
	if len(receipt.Limitations) == 0 {
		t.Fatal("credential gap must be explicit")
	}
}
