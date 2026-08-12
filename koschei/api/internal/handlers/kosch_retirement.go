package handlers

import "net/http"

// RetiredTokenAccessStatus keeps the legacy endpoint explicit for older clients
// while permanently removing token balance from SaaS authorization.
func (h *Handler) RetiredTokenAccessStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusGone, map[string]any{
		"ok":           false,
		"error":        "kosch_access_retired",
		"access_model": "saas_entitlement",
		"replacement":  "/api/auth/premium-access",
		"message":      "KOSCH holdings no longer grant product access. Paid access is determined only by an active SaaS entitlement.",
	})
}

// OwnerRetiredKOSCHAccess preserves the old owner route as an explicit tombstone
// so operators do not mistake historical KOSCH telemetry for current billing.
func (h *Handler) OwnerRetiredKOSCHAccess(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusGone, map[string]any{
		"ok":           false,
		"error":        "kosch_access_retired",
		"access_model": "saas_entitlement",
		"message":      "KOSCH holder access is retired. Historical token-access records are audit-only and cannot authorize customers.",
	})
}
