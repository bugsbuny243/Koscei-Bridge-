package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/services"
)

func (h *Handler) OwnerActorConstellation(w http.ResponseWriter, r *http.Request) {
	wallet := strings.TrimSpace(r.URL.Query().Get("wallet"))
	if wallet == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet is required"})
		return
	}
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}
	depth := parseBoundedActorConstellationInt(r.URL.Query().Get("depth"), 1, 3, 2)
	fanout := parseBoundedActorConstellationInt(r.URL.Query().Get("fanout"), 1, 20, 8)
	nodeCap := parseBoundedActorConstellationInt(r.URL.Query().Get("node_cap"), 2, 50, 25)

	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	report, err := services.NewActorDefenseStore(db).LoadActorConstellation(r.Context(), wallet, network, depth, fanout, nodeCap)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "actor constellation could not be loaded",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "constellation": report})
}

func parseBoundedActorConstellationInt(raw string, minValue, maxValue, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minValue || value > maxValue {
		return fallback
	}
	return value
}
