package handlers

import "net/http"

// RequireActiveEntitlement is kept as a compatibility wrapper for older call
// sites. Commercial access is determined only by an active Starter+ SaaS
// entitlement; KOSCH holdings are never consulted.
func (h *Handler) RequireActiveEntitlement(next http.HandlerFunc) http.HandlerFunc {
	return h.RequirePlanTier("starter", next)
}

func (h *Handler) RequirePremiumAccess(next http.HandlerFunc) http.HandlerFunc {
	return h.RequireActiveEntitlement(next)
}
