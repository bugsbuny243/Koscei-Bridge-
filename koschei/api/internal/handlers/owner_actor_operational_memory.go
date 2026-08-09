package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/services"
)

func (h *Handler) OwnerActorOperationalMemory(w http.ResponseWriter, r *http.Request) {
	wallet := strings.TrimSpace(r.URL.Query().Get("wallet"))
	if wallet == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet is required"})
		return
	}
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}
	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 1 && parsed <= 100 {
			limit = parsed
		}
	}
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	report, err := services.NewActorDefenseStore(db).LoadOperationalMemoryMatches(r.Context(), wallet, network, limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "actor operational memory could not be loaded",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "operational_memory": report})
}
