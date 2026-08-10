package handlers

import (
	"net/http"
	"strings"
)

// RequireAPIKeyKOSCH remains a basic-tier compatibility wrapper. New developer
// API routes use RequireAPIKeyTokenTier("enterprise", ...).
func (h *Handler) RequireAPIKeyKOSCH(next http.HandlerFunc) http.HandlerFunc {
	return h.RequireAPIKeyTokenTier("basic", next)
}

// RequireAPIKeyTokenTier binds an authenticated API key to the verified KOSCH
// tier of its owning account. API keys are identity credentials; they never
// bypass wallet verification or token eligibility. KOSCH authorization is
// additionally constrained by kosch_security_policy.go so holdings can grant
// access/capacity only, never evidence/verdict/security authority.
func (h *Handler) RequireAPIKeyTokenTier(required string, next http.HandlerFunc) http.HandlerFunc {
	required = strings.ToLower(strings.TrimSpace(required))
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := apiPrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if tokenTierRank(required) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "invalid_required_token_tier"})
			return
		}
		evaluation, err := h.evaluateTokenAccess(r.Context(), principal.AuthSubject)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "kosch_access_unavailable"})
			return
		}
		if !evaluation.GateEnabled || !evaluation.Configured || !evaluation.WalletVerified || !koschTierAuthorizes(evaluation.Tier, required) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "token_tier_required", "required_tier": required, "current_tier": evaluation.Tier,
			})
			return
		}
		ctx := withTokenAccessRequestContext(r.Context(), tokenAccessRequestContext{
			Evaluation: evaluation, AuthSubject: principal.AuthSubject, Email: principal.Email,
		})
		next(w, r.WithContext(ctx))
	}
}
