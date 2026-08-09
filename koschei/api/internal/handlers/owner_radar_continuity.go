package handlers

import (
	"net/http"
	"time"

	"koschei/api/internal/services"
)

func (h *Handler) OwnerRadarContinuity(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	readDB := h.DBRead
	if readDB == nil {
		readDB = h.DB
	}
	report, err := services.LoadSecurityRadarContinuity(r.Context(), readDB)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":           false,
			"status":       "continuity_unavailable",
			"generated_at": now,
			"error":        "stream continuity state could not be loaded",
		})
		return
	}
	// Inbox health is read from the primary when available because retry/exhausted
	// transitions are operational state and should not be hidden by replica lag.
	inboxDB := h.DB
	if inboxDB == nil {
		inboxDB = readDB
	}
	pumpHealth, err := services.LoadPumpPortalInboxHealth(r.Context(), inboxDB, now)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":           false,
			"status":       "continuity_unavailable",
			"generated_at": now,
			"error":        "PumpPortal durable ingress health could not be loaded",
			"continuity":   report,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"generated_at":      now,
		"continuity":        report,
		"pumpportal_ingest": pumpHealth,
	})
}
