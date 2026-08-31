package handlers

import (
	"net/http"
	"os"
	"strings"
)

const commercialCheckoutEnv = "KOSCHEI_COMMERCIAL_CHECKOUT_ENABLED"

// PolarCheckoutCommercial is the only customer checkout entry point exposed by
// the HTTP router. New checkout creation is fail-closed until commercial
// readiness is explicitly enabled in the server environment. Polar webhooks and
// existing entitlements are intentionally not affected by this gate.
func (h *Handler) PolarCheckoutCommercial(w http.ResponseWriter, r *http.Request) {
	if !commercialCheckoutEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":      false,
			"error":   "commercial_checkout_paused",
			"message": "New paid checkout is temporarily paused while production evidence coverage is being completed.",
		})
		return
	}
	h.PolarCheckout(w, r)
}

func commercialCheckoutEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(commercialCheckoutEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
