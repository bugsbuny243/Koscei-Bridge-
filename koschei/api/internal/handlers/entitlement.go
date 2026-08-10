package handlers

import (
	"context"
	"net/http"
)

// RequireActiveEntitlement is kept as a compatibility wrapper for existing
// route wiring. Access is now granted only through verified KOSCH holdings and
// the non-authority capability policy in kosch_security_policy.go.
func (h *Handler) RequireActiveEntitlement(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := userFromContext(r.Context())
		if !ok {
			writeAPIError(w, http.StatusUnauthorized, APICodeUnauthorized, "Unauthorized", nil)
			return
		}
		active, err := h.hasTokenTierAccess(r.Context(), claims.Sub, "basic")
		if err != nil {
			writeAPIError(w, http.StatusServiceUnavailable, APICodeInternalError, "KOSCH access could not be verified", nil)
			return
		}
		if !active {
			writeAPIError(w, http.StatusForbidden, APICodePackageRequired, "Verified KOSCH holder access required", nil)
			return
		}
		next(w, r)
	}
}

func (h *Handler) RequirePremiumAccess(next http.HandlerFunc) http.HandlerFunc {
	return h.RequireActiveEntitlement(next)
}

func (h *Handler) hasTokenTierAccess(ctx context.Context, authSubject string, requiredTier string) (bool, error) {
	evaluation, err := h.evaluateTokenAccess(ctx, authSubject)
	if err != nil {
		return false, err
	}
	if !evaluation.GateEnabled || !evaluation.Configured || !evaluation.WalletVerified {
		return false, nil
	}
	return koschTierAuthorizes(evaluation.Tier, requiredTier), nil
}
