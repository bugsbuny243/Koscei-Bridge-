package handlers

import (
	"context"
	"net/http"
	"time"
)

func (h *Handler) ownerUnifiedTransactionRadar(w http.ResponseWriter, r *http.Request, target, network string, classification radarTargetClassification) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	history := h.loadLatestIntelligenceMemory(ctx, "transaction_investigation", network, target)
	report := h.investigateTransactionSignature(ctx, target, network)
	writeJSON(w, http.StatusOK, customerTransactionInvestigationEnvelope(report, classification, false, history))
}
