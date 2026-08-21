package http

import (
	"net/http"

	"koschei/api/internal/handlers"
)

func registerBillingRoutes(mux *http.ServeMux, h *handlers.Handler) {
	checkout := requiresDB(h, handlers.RequireAuth(method(http.MethodPost, h.PaddleCheckout)))
	webhook := requiresDB(h, method(http.MethodPost, h.PaddleWebhook))
	publicConfig := method(http.MethodGet, h.PaddlePublicConfig)

	// Browser-only bootstrap surface for Paddle.js. Keep this outside /api/ so
	// it is not advertised as a public programmatic API contract.
	mux.HandleFunc("/paddle/public-config", publicConfig)
	mux.HandleFunc("/api/paddle/checkout", checkout)
	mux.HandleFunc("/api/v1/paddle/checkout", checkout)
	mux.HandleFunc("/api/paddle/webhook", webhook)
}
