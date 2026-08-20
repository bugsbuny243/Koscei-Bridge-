package handlers

import (
	"net/http"
	"strings"

	"koschei/api/internal/services"
)

// PaddlePublicConfig exposes only the browser-safe Paddle values required to
// initialize Paddle.js. API keys and webhook secrets never leave the server.
func (h *Handler) PaddlePublicConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := services.LoadPaddleConfigFromEnv()
	ready := cfg.AutomationReady && cfg.AllPlansReady && cfg.ClientTokenConfigured
	status := cfg.PublicStatus()

	payload := map[string]any{
		"ok":           ready,
		"environment":  cfg.Environment,
		"client_token": cfg.ClientToken,
		"checkout_url": cfg.CheckoutURL,
		"success_url":  strings.TrimRight(cfg.PublicAppURL, "/") + "/account?payment=paddle_success",
		"cancel_url":   strings.TrimRight(cfg.PublicAppURL, "/") + "/pricing?payment=paddle_cancelled",
		"paddle":       status,
	}
	if !cfg.ClientTokenConfigured {
		payload["client_token"] = ""
	}
	if !ready {
		writeJSON(w, http.StatusServiceUnavailable, payload)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}
