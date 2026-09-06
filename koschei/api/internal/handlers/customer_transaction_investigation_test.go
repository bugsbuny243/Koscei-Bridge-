package handlers

import "testing"

func TestCustomerRadarAllowsTransactionSignatureDispatch(t *testing.T) {
	classification := radarTargetClassification{Type: radarTargetTransactionSignature}
	if !radarTargetWalletInvestigationAllowed(classification) {
		t.Fatal("transaction signature must enter the customer investigation dispatcher")
	}
	if _, err := resolveCustomerWalletTarget("signature", classification); err == nil {
		t.Fatal("transaction signature must not masquerade as a wallet target")
	}
}

func TestCustomerTransactionEnvelopeWithholdsMaliciousnessVerdict(t *testing.T) {
	report := newTransactionInvestigationReport("sig111", "solana-mainnet")
	report.Status = "complete"
	report.EvidenceRefs = []string{"rpc:getTransaction"}
	classification := radarTargetClassification{Type: radarTargetTransactionSignature}
	envelope := customerTransactionInvestigationEnvelope(report, classification, true)
	if envelope["status"] != "evidence_available" {
		t.Fatalf("status=%v", envelope["status"])
	}
	if envelope["charged"] != true {
		t.Fatal("published transaction evidence should preserve charged=true metadata")
	}
	verdict, _ := envelope["final_verdict"].(map[string]any)
	if verdict["withheld"] != true || verdict["risk_level"] != "unknown" {
		t.Fatalf("verdict=%+v", verdict)
	}
	policy, _ := envelope["evidence_policy"].(map[string]any)
	if policy["neon_intelligence_persistence"] != false || policy["durable_memory_backend"] != "google_drive" {
		t.Fatalf("storage policy=%+v", policy)
	}
}

func TestCustomerTransactionGapIsShareableWithoutCharge(t *testing.T) {
	report := newTransactionInvestigationReport("sig111", "solana-mainnet")
	report.Status = "transaction_unavailable"
	report.CollectionGaps = []string{"provider returned no transaction"}
	envelope := customerTransactionInvestigationEnvelope(report, radarTargetClassification{Type: radarTargetTransactionSignature}, false)
	if envelope["status"] != "evidence_gap" {
		t.Fatalf("status=%v", envelope["status"])
	}
	if envelope["charged"] != false {
		t.Fatal("evidence gap must not consume a premium output")
	}
}
