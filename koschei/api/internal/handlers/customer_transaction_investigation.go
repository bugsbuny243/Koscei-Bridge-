package handlers

import (
	"context"
	"net/http"
	"time"
)

func transactionInvestigationPublished(report transactionInvestigationReport) bool {
	return report.Status == "complete" && len(report.EvidenceRefs) > 0
}

func customerTransactionInvestigationEnvelope(report transactionInvestigationReport, classification radarTargetClassification, charged bool, historical ...intelligenceMemoryReadReceipt) map[string]any {
	status := "evidence_gap"
	if transactionInvestigationPublished(report) {
		status = "evidence_available"
	}
	history := intelligenceMemoryReadReceipt{
		Status:      "not_requested",
		Backend:     "google_drive",
		Limitations: []string{},
	}
	if len(historical) > 0 {
		history = historical[0]
	}
	return map[string]any{
		"ok":                    true,
		"status":                status,
		"investigation_kind":    "transaction_execution_evidence",
		"schema_version":        transactionInvestigationSchemaVersion,
		"target":                report.Signature,
		"network":               report.Network,
		"target_classification": classification,
		"transaction":           report,
		"historical_memory":     history,
		"charged":               charged,
		"final_verdict": map[string]any{
			"grade":      "-",
			"risk_level": "unknown",
			"signed":     false,
			"verdict":    "Historical execution evidence is reported without fabricating a maliciousness verdict.",
			"withheld":   true,
		},
		"evidence_policy": map[string]any{
			"historical_execution_is_not_presigning_intent": true,
			"historical_memory_cannot_override_live_evidence": true,
			"signer_is_not_real_world_identity":               true,
			"program_id_is_not_bytecode_semantics":            true,
			"missing_evidence_is_not_safe":                    true,
			"raw_transaction_saved":                           false,
			"durable_memory_backend":                          "google_drive",
			"neon_intelligence_persistence":                   false,
		},
	}
}

func (h *Handler) securityRadarTransactionCheck(w http.ResponseWriter, r *http.Request, authSubject, claimEmail, target, network string, classification radarTargetClassification) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	// Read the prior verified snapshot before the live investigation writes the
	// current snapshot, otherwise "historical" context would merely echo this run.
	history := h.loadLatestIntelligenceMemory(ctx, "transaction_investigation", network, target)
	report := h.investigateTransactionSignature(ctx, target, network)

	charged := false
	if transactionInvestigationPublished(report) {
		if err := h.consumePremiumOutput(authSubject, claimEmail, "security_radar_transaction_check"); err != nil {
			writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
			return
		}
		charged = true
	}
	h.logTool(claimEmail, "security_radar_transaction_check", report.Status)
	h.trackEvent(claimEmail, "security_radar_transaction_check", r.URL.Path)
	writeJSON(w, http.StatusOK, customerTransactionInvestigationEnvelope(report, classification, charged, history))
}
