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
	// Ingress and trade delivery are operational state. Prefer the primary so
	// replica lag cannot hide a retry, exhausted row or newly committed trade.
	operationalDB := h.DB
	if operationalDB == nil {
		operationalDB = readDB
	}
	pumpHealth, err := services.LoadPumpPortalInboxHealth(r.Context(), operationalDB, now)
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
	tradeHealth, err := services.LoadPumpPortalTradeStreamHealth(r.Context(), operationalDB, now)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":                false,
			"status":            "continuity_unavailable",
			"generated_at":      now,
			"error":             "PumpPortal trade-stream health could not be loaded",
			"continuity":        report,
			"pumpportal_ingest": pumpHealth,
		})
		return
	}
	providerMemory, err := services.LoadProviderWitnessMemory(r.Context(), readDB, "solana-mainnet", "", 50)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":                      false,
			"status":                  "continuity_unavailable",
			"generated_at":            now,
			"error":                   "provider witness memory could not be loaded",
			"continuity":              report,
			"pumpportal_ingest":       pumpHealth,
			"pumpportal_trade_stream": tradeHealth,
		})
		return
	}
	posture := services.DeriveSecurityIntegrityPosture(report, pumpHealth, tradeHealth, providerMemory)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                      true,
		"generated_at":            now,
		"integrity_posture":       posture,
		"continuity":              report,
		"pumpportal_ingest":       pumpHealth,
		"pumpportal_trade_stream": tradeHealth,
		"provider_witness_memory": providerMemory,
	})
}
