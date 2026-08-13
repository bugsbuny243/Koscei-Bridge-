package handlers

import (
	"net/http"
	"strings"
)

// DossierAccess accepts owner credentials, Enterprise API keys or an Enterprise
// SaaS user session. The selected path is explicit so one credential type never
// falls through into another authentication mechanism. The resulting export
// remains private by default even when the canonical bundle itself is durable.
func (h *Handler) DossierAccess(next http.HandlerFunc) http.HandlerFunc {
	next = privateDossierExport(next)
	return func(w http.ResponseWriter, r *http.Request) {
		if dossierOwnerCredentialPresent(r) {
			if !h.OwnerAuth(w, r) {
				return
			}
			next(w, r)
			return
		}
		apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
		bearer := bearerToken(r.Header.Get("Authorization"))
		if apiKey != "" || strings.HasPrefix(bearer, "kch_live_") {
			h.APIKeyAuth(h.RequireAPIKeyPlanTier("enterprise", next))(w, r)
			return
		}
		RequireAuth(h.RequirePlanTier("enterprise", next))(w, r)
	}
}

func dossierOwnerCredentialPresent(r *http.Request) bool {
	for _, name := range []string{"x-koschei-secret", "x-owner-secret", "x-admin-password"} {
		if strings.TrimSpace(r.Header.Get(name)) != "" {
			return true
		}
	}
	if cookie, err := r.Cookie("koschei_owner_secret"); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return true
	}
	return false
}
