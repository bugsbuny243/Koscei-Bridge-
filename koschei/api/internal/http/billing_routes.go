package http

import (
	"net/http"

	"koschei/api/internal/handlers"
)

// Billing-provider routes are intentionally narrow. Checkout requires a
// customer session and passes through a fail-closed commercial-readiness gate;
// webhook access is public at the HTTP edge but authorizes no product access
// until its Polar signature and server-side binding evidence are verified by
// the handler.
func registerBillingRoutes(mux *http.ServeMux, h *handlers.Handler) {
	mux.HandleFunc("/api/polar/checkout", requiresDB(h, handlers.RequireAuth(method(http.MethodPost, h.PolarCheckoutCommercial))))
	mux.HandleFunc("/api/polar/webhook", requiresDB(h, method(http.MethodPost, h.PolarWebhook)))
}
