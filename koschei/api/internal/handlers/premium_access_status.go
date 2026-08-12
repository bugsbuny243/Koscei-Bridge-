package handlers

import "net/http"

type premiumAccessStatus struct {
	Active           bool   `json:"active"`
	Source           string `json:"source"`
	Plan             string `json:"plan"`
	RequiredPlan     string `json:"required_plan"`
	OutputsTotal     int    `json:"outputs_total"`
	OutputsRemaining int    `json:"outputs_remaining"`
	StartsAt         any    `json:"starts_at,omitempty"`
	ExpiresAt        any    `json:"expires_at,omitempty"`
}

func (h *Handler) PremiumAccessStatus(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	evaluation, err := h.evaluatePlanAccess(r.Context(), claims.Sub, normalizedClaimEmail(claims))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plan_access_unavailable"})
		return
	}
	status := premiumAccessStatus{
		Active:           evaluation.Active,
		Source:           "entitlement",
		Plan:             evaluation.Plan,
		RequiredPlan:     "starter",
		OutputsTotal:     evaluation.OutputsTotal,
		OutputsRemaining: evaluation.OutputsRemaining,
		StartsAt:         evaluation.StartsAt,
		ExpiresAt:        evaluation.ExpiresAt,
	}
	if status.Plan == "" {
		status.Plan = "none"
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "access": status})
}
