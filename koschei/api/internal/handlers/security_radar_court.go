package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type securityRadarCourtRequest struct {
	Target   string `json:"target"`
	Address  string `json:"address"`
	Network  string `json:"network"`
	Extended bool   `json:"extended,omitempty"`
}

// SecurityRadarCourt builds the same immutable evidence packet used by the
// owner Tribunal, but applies the authenticated SaaS plan. Professional receives
// two prosecutors and the conditional first-instance panel. Enterprise may also
// receive the senior panel. Starter never reaches this Professional-gated route.
func (h *Handler) SecurityRadarCourt(w http.ResponseWriter, r *http.Request) {
	var input securityRadarCourtRequest
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
	if !radarTargetTokenVerdictAllowed(classification) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": "token_mint_required",
			"message": radarTargetRejectionMessage(classification),
			"target":  target, "target_classification": classification,
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 360*time.Second)
	defer cancel()
	assembly := h.buildUnifiedInvestigationReport(ctx, target, network, "customer_court_review")
	core := assembly.Core
	hasLiveEvidence := services.SecurityRadarHasLiveEvidence(core.Bundle)
	_ = h.saveSecurityRadarBundle(ctx, courtRequestIdentity(ctx), "customer_court_review", core.Bundle)

	unifiedVerdict := assembly.UnifiedVerdict
	unifiedPersistence, unifiedHistory := h.persistUnifiedRadarVerdict(ctx, assembly.DB, network, "token", target, unifiedVerdict, assembly.Behavior)
	courtInput := CourtReadOnlyInput{
		Target:        target,
		Network:       network,
		SignedVerdict: unifiedVerdict,
		VerdictCard: map[string]any{
			"grade":     unifiedVerdict.Grade,
			"verdict":   unifiedVerdict.Verdict,
			"signed":    unifiedVerdict.Signed,
			"signature": unifiedVerdict.Signature,
		},
		EvidencePacket: map[string]any{
			"investigation_report": assembly.Report,
			"threat_anticipation":  assembly.Threat,
			"behavior_signals":     assembly.Behavior,
			"actor_rule_verdict":   assembly.ActorVerdict,
			"actor_evidence":       assembly.CombinedEvidence,
			"holder_intelligence":  core.Intelligence,
			"holder_cluster":       core.Cluster,
			"market":               core.Market,
			"modules":              assembly.Modules,
			"evidence":             radarDetailEvidence(core.Arms),
			"graph":                assembly.Graph,
		},
	}
	court := h.courtNarrative(ctx, courtInput, input.Extended)
	if court == nil || court.Status == "skipped" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":                   false,
			"error":                "court_unavailable",
			"message":              "ARVIS Tribunal is disabled or its provider client is not configured.",
			"investigation_status": customerInvestigationStatus(unifiedVerdict, hasLiveEvidence),
			"has_live_evidence":    hasLiveEvidence,
			"final_verdict":        unifiedVerdict,
			"threat_anticipation":  assembly.Threat,
			"investigation_report": assembly.Report,
			"court":                court,
		})
		return
	}
	status := http.StatusOK
	if court.Status == "error" {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, map[string]any{
		"ok":                        court.Status != "error",
		"schema_version":            "koschei-arvis-court-v1",
		"target":                    target,
		"network":                   network,
		"tier_applied":              court.TierApplied,
		"investigation_status":      customerInvestigationStatus(unifiedVerdict, hasLiveEvidence),
		"has_live_evidence":         hasLiveEvidence,
		"final_verdict":             unifiedVerdict,
		"final_verdict_persistence": unifiedPersistence,
		"final_verdict_history":     unifiedHistory,
		"threat_anticipation":       assembly.Threat,
		"investigation_report":      assembly.Report,
		"court":                     court,
		"evidence_policy": map[string]any{
			"signed_deterministic_verdict_is_authoritative": true,
			"court_is_read_only_commentary":                 true,
			"numeric_final_score_disabled":                  true,
			"numeric_rug_probability_disabled":              true,
			"no_evidence_no_claim":                          true,
			"unsigned_investigation_is_not_server_failure":  true,
		},
	})
}

func courtRequestIdentity(ctx context.Context) string {
	if access, ok := planAccessRequestFromContext(ctx); ok {
		return firstNonEmptyString(access.AuthSubject, access.Email)
	}
	if claims, ok := userFromContext(ctx); ok {
		return claims.Sub
	}
	return ""
}
