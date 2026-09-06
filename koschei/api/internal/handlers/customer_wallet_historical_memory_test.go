package handlers

import "testing"

func TestCustomerWalletInvestigationEnvelopeIncludesHistoricalDriveContext(t *testing.T) {
	result := customerWalletInvestigationResult{
		Target:  "wallet-target",
		Wallet:  "wallet-target",
		Network: "solana-mainnet",
		HistoricalMemory: intelligenceMemoryReadReceipt{
			Status:    "verified_history_available",
			Available: true,
			Backend:   "google_drive",
		},
	}

	envelope := customerWalletInvestigationEnvelope(result, false)
	history, ok := envelope["historical_memory"].(intelligenceMemoryReadReceipt)
	if !ok {
		t.Fatalf("historical_memory type = %T, want intelligenceMemoryReadReceipt", envelope["historical_memory"])
	}
	if history.Status != "verified_history_available" || !history.Available || history.Backend != "google_drive" {
		t.Fatalf("historical_memory = %#v", history)
	}

	policy, ok := envelope["evidence_policy"].(map[string]any)
	if !ok {
		t.Fatalf("evidence_policy type = %T", envelope["evidence_policy"])
	}
	if policy["historical_memory_cannot_override_live_evidence"] != true {
		t.Fatalf("historical memory precedence policy missing: %#v", policy)
	}
	if policy["neon_intelligence_persistence"] != false {
		t.Fatalf("Neon intelligence persistence must remain disabled: %#v", policy)
	}
	if policy["durable_memory_backend"] != "google_drive" {
		t.Fatalf("durable memory backend = %v, want google_drive", policy["durable_memory_backend"])
	}
}
