package handlers

import "net/http"

// RetiredTokenAccessStatus is a compatibility tombstone for retired legacy access clients.
func (h *Handler) RetiredTokenAccessStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusGone, map[string]any{
		"ok": false,
		"error": "legacy_access_retired",
		"access_model": "saas_entitlement",
		"replacement": "/api/auth/premium-access",
		"message": "Legacy asset-based access is retired. Paid access is determined only by an active SaaS entitlement.",
	})
}

// OwnerRetiredKOSCHAccess is retained only because the historical owner route still references this handler.
// It grants no access and returns HTTP 410 Gone.
func (h *Handler) OwnerRetiredKOSCHAccess(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusGone, map[string]any{
		"ok": false,
		"error": "legacy_access_retired",
		"access_model": "saas_entitlement",
		"message": "Legacy asset-based access is retired and cannot authorize customers.",
	})
}
