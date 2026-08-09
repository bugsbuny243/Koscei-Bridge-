package handlers

import (
	"net/http"
	"time"

	"koschei/api/internal/services"
)

func (h *Handler) OwnerRadarContinuity(w http.ResponseWriter, r *http.Request) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	report, err := services.LoadSecurityRadarContinuity(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":           false,
			"status":       "continuity_unavailable",
			"generated_at": time.Now().UTC(),
			"error":        "stream continuity state could not be loaded",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"generated_at": time.Now().UTC(),
		"continuity":   report,
	})
}
