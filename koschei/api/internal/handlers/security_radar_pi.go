package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const piCustomerInvestigationSchemaVersion = "koschei-customer-pi-investigation-v2"

func securityRadarInputIsPi(input securityRadarInput) bool {
	target := strings.TrimSpace(firstNonEmptyString(input.Target, input.Address))
	if _, ok := services.NormalizePiRadarNetwork(input.Network); ok {
		return true
	}
	_, ok := services.ParsePiRadarTarget(target)
	return ok
}

// SecurityRadarPiCheck is intentionally separate from the Solana unified
// investigation assembler. Pi evidence must never flow through SPL/Pump/Raydium
// collectors just because the customer uses the same ARVIS product route.
func (h *Handler) SecurityRadarPiCheck(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, APICodeUnauthorized, "Unauthorized")
		return
	}
	claimEmail := normalizedClaimEmail(claims)
	if _, err := h.requirePremiumOutput(claims.Sub, claimEmail); err != nil {
		writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
		return
	}
	var input securityRadarInput
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid request body")
		return
	}
	target := strings.TrimSpace(firstNonEmptyString(input.Target, input.Address))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	piTarget, validTarget := services.ParsePiRadarTarget(target)
	if !validTarget {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"ok": false, "error": "pi_target_required", "message": "Pi Radar expects a public G-address or an asset in CODE:G...ISSUER form.", "target": target, "charged": false, "final_verdict": map[string]any{"grade": "-", "risk_index": nil, "risk_level": "unknown", "signed": false, "recommendation": "provide_pi_public_account_or_asset"}})
		return
	}
	network := services.DefaultPiRadarNetwork()
	if strings.TrimSpace(input.Network) != "" {
		normalized, piNetwork := services.NormalizePiRadarNetwork(input.Network)
		if !piNetwork {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"ok": false, "error": "pi_network_mismatch", "message": "The target is a Pi target. Select Pi Mainnet or Pi Testnet; ARVIS will not reinterpret it as another chain.", "target": target, "network": input.Network, "charged": false})
			return
		}
		network = normalized
	}
	label := services.PiRadarNetworkLabel(network)
	mode := firstNonEmptyString(input.Mode, "manual_dashboard_check")
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "radar_pi_check_requested", "customer", "info", map[string]any{"network": network, "mode": mode, "target": target, "kind": piTarget.Kind}))
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	analysis := services.AnalyzeArvisRadarsMultiChainContext(ctx, services.SecurityRadarRequest{Target: target, Network: network, Mode: mode})
	observed := piObservedArmCount(analysis.Arms)
	hasEvidence := observed > 0
	_ = h.saveSecurityRadarBundle(ctx, claims.Sub, "manual_pi_check", analysis.Bundle)
	charged := false
	if hasEvidence {
		if err := h.consumePremiumOutput(claims.Sub, claimEmail, "security_radar_pi_check"); err != nil {
			writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
			return
		}
		charged = true
	}
	status := "evidence_pending"
	message := label + " evidence collection is incomplete; missing evidence is not treated as safe."
	if hasEvidence {
		message = label + " evidence collected. A signed Pi risk grade is withheld until the Pi-specific deterministic ruleset is validated."
	}
	h.logTool(claimEmail, "security_radar_pi_check", status)
	h.trackEvent(claimEmail, "security_radar_pi_check", r.URL.Path)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "response_schema_version": piCustomerInvestigationSchemaVersion, "status": status, "message": message,
		"target": target, "target_kind": piTarget.Kind, "network": network, "network_label": label, "provider": analysis.Bundle.Provider,
		"has_live_evidence": hasEvidence, "observed_arm_count": observed, "charged": charged, "bundle": analysis.Bundle, "arms": analysis.Arms, "final_verdict": analysis.Final,
		"analysis_summary":     map[string]any{"decision": "review_pi_evidence", "why": message, "observed_arm_count": observed, "signed": false, "risk_level": "unknown", "network": network},
		"investigation_report": map[string]any{"chain": "pi", "chain_adapter": "pi_horizon_v2", "target": target, "target_kind": piTarget.Kind, "network": network, "network_label": label, "provider": analysis.Bundle.Provider, "evidence_arms": analysis.Arms, "intelligence_graph": analysis.Graph, "metadata": analysis.Bundle.Metadata, "final_verdict": analysis.Final},
		"evidence_policy":      map[string]any{"missing_evidence_is_not_safe": true, "numeric_final_score_disabled": true, "pi_signed_grade_enabled": false, "wallet_secrets_required": false, "server_transaction_submission_enabled": false, "cross_chain_reinterpretation_allowed": false},
	})
}

func piObservedArmCount(arms []services.SecurityRadarVerdict) int {
	count := 0
	for _, arm := range arms {
		if strings.EqualFold(strings.TrimSpace(stringFromMap(arm.Signals, "evidence_status")), "observed") {
			count++
		}
	}
	return count
}
