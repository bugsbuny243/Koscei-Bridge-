package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestAttachArvisIntelligenceBridgePreservesExistingReportAndAddsContract(t *testing.T) {
	observedAt := time.Date(2026, 9, 6, 6, 0, 0, 0, time.UTC)
	assembly := unifiedInvestigationAssembly{
		Core: holderIntelligenceCoreResult{Request: services.SecurityRadarRequest{
			Target:  "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump",
			Network: "solana-mainnet",
		}},
		Report: map[string]any{
			"final_verdict": "existing-arvis-verdict",
			"transaction_evidence": []unifiedTransactionEvidence{{
				Signature: "sig-bridge",
				Slot:      444,
				Source:    "helius",
				BlockTime: &observedAt,
			}},
		},
	}

	attachArvisIntelligenceBridge(&assembly)

	if assembly.Report["final_verdict"] != "existing-arvis-verdict" {
		t.Fatal("bridge must not replace the existing ARVIS verdict")
	}
	projection, ok := assembly.Report["intelligence_contract"].(services.IntelligenceInvestigation)
	if !ok {
		t.Fatalf("expected typed intelligence contract, got %#v", assembly.Report["intelligence_contract"])
	}
	if len(projection.Evidence) != 1 || projection.Evidence[0].TransactionHash != "sig-bridge" {
		t.Fatalf("expected existing ARVIS transaction evidence to be projected: %#v", projection.Evidence)
	}
	if projection.Decision.Status != services.IntelligenceEvidenceUnverified {
		t.Fatalf("bridge must not synthesize a new verdict: %#v", projection.Decision)
	}
}
