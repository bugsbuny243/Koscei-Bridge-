package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type ownerInvestigationAcceptanceRequest struct {
	Target  string `json:"target"`
	Address string `json:"address"`
	Network string `json:"network"`
	Profile string `json:"profile"`
}

// OwnerInvestigationAcceptance runs one real full-scan path and evaluates the
// resulting report against the production truth contract. It is owner-only and
// uses the same evidence engine as public and API token scans.
func (h *Handler) OwnerInvestigationAcceptance(w http.ResponseWriter, r *http.Request) {
	var input ownerInvestigationAcceptanceRequest
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid request body")
		return
	}
	target := strings.TrimSpace(firstNonEmptyString(input.Target, input.Address))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	network := strings.TrimSpace(input.Network)
	if network == "" {
		network = "solana-mainnet"
	}
	classification := classifyRadarTarget(r.Context(), target)
	if classification.Type != radarTargetTokenMint {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": "acceptance_requires_token_mint", "target": target,
			"target_classification": classification,
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	assembly := h.buildUnifiedInvestigationReport(ctx, target, network, "owner_unified_manual_scan")
	acceptance := evaluateInvestigationAcceptance(assembly.Report, target, input.Profile)
	status := http.StatusOK
	if acceptance.Status == "fail" {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, map[string]any{
		"ok":                   acceptance.Status != "fail",
		"acceptance":           acceptance,
		"investigation_report": assembly.Report,
	})
}
