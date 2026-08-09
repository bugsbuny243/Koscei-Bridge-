package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/services"
)

func (h *Handler) OwnerProviderWitnessMemory(w http.ResponseWriter, r *http.Request) {
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}
	method := strings.TrimSpace(r.URL.Query().Get("method"))
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 1 && parsed <= 100 {
			limit = parsed
		}
	}
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	report, err := services.LoadProviderWitnessMemory(r.Context(), db, network, method, limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "provider witness memory could not be loaded",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provider_memory": report})
}
