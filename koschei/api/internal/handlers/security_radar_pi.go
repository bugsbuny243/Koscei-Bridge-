package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const piCustomerInvestigationSchemaVersion = "koschei-customer-pi-investigation-v1"

func securityRadarInputIsPi(input securityRadarInput) bool {
	target := strings.TrimSpace(firstNonEmptyString(input.Target, input.Address))
	if services.IsPiRadarNetwork(input.Network) {
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
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok":      false,
			"error":   "pi_target_required",
			"message": "Pi Radar expects a public G-address or an asset in CODE:G...ISSUER form.",
			"target":  target,
			"charged": false,
			"final_verdict": map[string]any{
				"grade":          "-",
				"risk_index":     nil,
				"risk_level":     "unknown",
				"signed":         false,
				"recommendation": "provide_pi_public_account_or_asset",
			},
		})
		return
	}
	if strings.TrimSpace(input.Network) != "" && !services.IsPiRadarNetwork(input.Network) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok":      false,
			"error":   "pi_network_mismatch",
			"message": "The target is a Pi target but the requested network is not Pi Testnet.",
			"target":  target,
			"network": input.Network,
			"charged": false,
		})
		return
	}

	mode := firstNonEmptyString(input.Mode, "manual_dashboard_check")
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "radar_pi_check_requested", "customer", "info", map[string]any{
		"network": "pi-testnet",
		"mode":    mode,
		"target":  target,
		"kind":    piTarget.Kind,
	}))

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	analysis := services.AnalyzeArvisRadarsMultiChainContext(ctx, services.SecurityRadarRequest{Target: target, Network: "pi-testnet", Mode: mode})
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
	message := "Pi Testnet evidence collection is incomplete; missing evidence is not treated as safe."
	if hasEvidence {
		message = "Pi Testnet evidence collected. A signed Pi risk grade is withheld until the Pi-specific deterministic ruleset is validated."
	}
	h.logTool(claimEmail, "security_radar_pi_check", status)
	h.trackEvent(claimEmail, "security_radar_pi_check", r.URL.Path)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                      true,
		"response_schema_version": piCustomerInvestigationSchemaVersion,
		"status":                  status,
		"message":                 message,
		"target":                  target,
		"target_kind":             piTarget.Kind,
		"network":                 "pi-testnet",
		"provider":                analysis.Bundle.Provider,
		"has_live_evidence":       hasEvidence,
		"observed_arm_count":      observed,
		"charged":                 charged,
		"bundle":                  analysis.Bundle,
		"arms":                    analysis.Arms,
		"final_verdict":           analysis.Final,
		"analysis_summary": map[string]any{
			"decision":           "review_pi_evidence",
			"why":                message,
			"observed_arm_count": observed,
			"signed":             false,
			"risk_level":         "unknown",
		},
		"investigation_report": map[string]any{
			"chain_adapter":      "pi_horizon_v1",
			"target":             target,
			"target_kind":        piTarget.Kind,
			"network":            "pi-testnet",
			"provider":           analysis.Bundle.Provider,
			"evidence_arms":      analysis.Arms,
			"intelligence_graph": analysis.Graph,
			"metadata":           analysis.Bundle.Metadata,
			"final_verdict":      analysis.Final,
		},
		"evidence_policy": map[string]any{
			"missing_evidence_is_not_safe":          true,
			"numeric_final_score_disabled":          true,
			"pi_signed_grade_enabled":               false,
			"wallet_secrets_required":               false,
			"server_transaction_submission_enabled": false,
		},
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
