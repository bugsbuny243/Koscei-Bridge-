package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

// OwnerRadarOverviewFast keeps the owner workspace responsive even when the
// historical radar tables are large. Each read is bounded and failures return
// partial production data instead of holding the whole page open.
func (h *Handler) OwnerRadarOverviewFast(w http.ResponseWriter, r *http.Request) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	items := []services.SecurityRadarVerdictRecord{}
	sources := []services.SecurityRadarSource{}
	highVolumePump := []services.PumpHighVolumeOwnerItem{}

	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if db != nil {
		store := services.NewSecurityRadarStore(db)
		if loaded, err := store.LatestVerdicts(ctx, 40); err == nil {
			items = loaded
		}
		if loaded, err := store.ListSources(ctx); err == nil {
			sources = loaded
		}
		if loaded, err := store.LatestPumpHighVolumeReportsExact(ctx, 50); err == nil {
			highVolumePump = loaded
		}
		items = withoutPumpHighVolumeLegacyFinals(items, highVolumePump)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "generated_at": time.Now().UTC(), "items": items,
		"high_volume_pump": highVolumePump,
		"sources":          sources, "pipeline": h.securityRadarStreamStats(ctx),
	})
}

// High-volume Pump rows now carry their own canonical job/report state. Sending
// the retired final_verdict_engine representative for the same Solana mint in
// parallel lets old clients merge legacy signed fields back over the canonical
// state. Exact target matching preserves Solana base58 case semantics.
func withoutPumpHighVolumeLegacyFinals(items []services.SecurityRadarVerdictRecord, pump []services.PumpHighVolumeOwnerItem) []services.SecurityRadarVerdictRecord {
	if len(items) == 0 || len(pump) == 0 {
		return items
	}
	targets := make(map[string]struct{}, len(pump))
	for _, row := range pump {
		if target := strings.TrimSpace(row.Target); target != "" {
			targets[target] = struct{}{}
		}
	}
	if len(targets) == 0 {
		return items
	}
	out := make([]services.SecurityRadarVerdictRecord, 0, len(items))
	for _, item := range items {
		if _, legacyPumpTarget := targets[strings.TrimSpace(item.Target)]; legacyPumpTarget {
			continue
		}
		out = append(out, item)
	}
	return out
}
