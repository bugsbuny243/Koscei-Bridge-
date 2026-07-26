package handlers

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"koschei/api/internal/services"
)

const (
	arvisHealthCacheTTL = 15 * time.Second
	publicHealthTimeout = 2 * time.Second
)

var arvisHealthCache = struct {
	sync.RWMutex
	data      map[string]any
	expiresAt time.Time
}{}

// Health is the public liveness/readiness endpoint used by Railway and external
// transport monitors. It must remain bounded and must not execute the full ARVIS
// operational query set. Detailed pipeline health remains on the dedicated
// Web3/owner health surfaces.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), publicHealthTimeout)
	defer cancel()
	if err := h.dbAvailable(ctx); err != nil {
		log.Printf("health check database ping failed: %v", err)
		payload := map[string]any{
			"status":   "error",
			"database": "unavailable",
			"service":  "koschei-web3",
			"arvis": map[string]any{
				"pipeline_status": "database_unavailable",
				"details_url":     "/api/web3/health",
			},
		}
		if !isProduction() {
			payload["details"] = err.Error()
		}
		writeJSON(w, http.StatusServiceUnavailable, payload)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"database": "connected",
		"service":  "koschei-web3",
		"arvis":    cachedArvisHealthSnapshot(),
	})
}

func cachedArvisHealthSnapshot() map[string]any {
	arvisHealthCache.RLock()
	defer arvisHealthCache.RUnlock()
	if arvisHealthCache.data == nil {
		return map[string]any{
			"pipeline_status": "not_sampled",
			"details_url":     "/api/web3/health",
			"cached":          false,
		}
	}
	out := make(map[string]any, len(arvisHealthCache.data)+3)
	for key, value := range arvisHealthCache.data {
		out[key] = value
	}
	out["cached"] = true
	out["cache_expires_at"] = arvisHealthCache.expiresAt.UTC().Format(time.RFC3339)
	out["details_url"] = "/api/web3/health"
	return out
}

func (h *Handler) cachedArvisHealth(ctx context.Context) map[string]any {
	now := time.Now()
	arvisHealthCache.RLock()
	if arvisHealthCache.data != nil && now.Before(arvisHealthCache.expiresAt) {
		data := arvisHealthCache.data
		arvisHealthCache.RUnlock()
		return data
	}
	arvisHealthCache.RUnlock()

	arvisHealthCache.Lock()
	defer arvisHealthCache.Unlock()
	if arvisHealthCache.data != nil && now.Before(arvisHealthCache.expiresAt) {
		return arvisHealthCache.data
	}
	stats := h.securityRadarStreamStats(ctx)
	data := map[string]any{
		"pipeline_status":         stats["pipeline_status"],
		"architecture_arm_count":  stats["architecture_arm_count"],
		"runtime_engines":         stats["runtime_engines"],
		"raw_stream_events":       stats["raw_stream_events"],
		"recognized_events":       stats["recognized_events"],
		"enriched_mints":          stats["enriched_mints"],
		"visible_verdicts":        stats["visible_verdicts"],
		"signed_verdicts_total":   stats["signed_verdicts_total"],
		"processing_active":       stats["processing_active"],
		"processing_completed":    stats["processing_completed"],
		"processing_insufficient": stats["processing_insufficient"],
		"processing_failed":       stats["processing_failed"],
		"last_stream_event_at":    stats["last_stream_event_at"],
		"last_processed_at":       stats["last_processed_at"],
		"runtime_window_minutes":  stats["runtime_window_minutes"],
		"sources":                 h.arvisSourceHealth(ctx),
		"failures":                h.arvisFailureHealth(ctx),
		"cached_for_seconds":      int(arvisHealthCacheTTL.Seconds()),
	}
	arvisHealthCache.data = data
	arvisHealthCache.expiresAt = now.Add(arvisHealthCacheTTL)
	return data
}

func resetArvisHealthCache() {
	arvisHealthCache.Lock()
	arvisHealthCache.data = nil
	arvisHealthCache.expiresAt = time.Time{}
	arvisHealthCache.Unlock()
}

func (h *Handler) arvisSourceHealth(ctx context.Context) map[string]any {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return map[string]any{}
	}
	return map[string]any{
		"pump":    arvisModuleSourceHealth(ctx, db, services.ModulePumpSybilRadar),
		"raydium": arvisModuleSourceHealth(ctx, db, services.ModuleRaydiumPoolGuardian),
	}
}

func (h *Handler) arvisFailureHealth(ctx context.Context) map[string]any {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	out := map[string]any{
		"retryable":         int64(0),
		"exhausted":         int64(0),
		"recent_15_minutes": int64(0),
		"latest_error_code": "",
		"latest_error_at":   "",
		"reason_counts":     map[string]int64{},
	}
	if db == nil {
		return out
	}

	var retryable, exhausted, recent int64
	var latestAt string
	if err := db.QueryRowContext(ctx, `
		SELECT
			count(*) FILTER (WHERE status='failed' AND attempts < 3),
			count(*) FILTER (WHERE status='exhausted' OR (status='failed' AND attempts >= 3)),
			count(*) FILTER (WHERE status='failed' AND attempts < 3 AND updated_at > now() - interval '15 minutes'),
			COALESCE(max(updated_at) FILTER (WHERE status IN ('failed','exhausted'))::text,'')
		FROM arvis_stream_processing
	`).Scan(&retryable, &exhausted, &recent, &latestAt); err == nil {
		out["retryable"] = retryable
		out["exhausted"] = exhausted
		out["recent_15_minutes"] = recent
		out["latest_error_at"] = latestAt
	}

	rows, err := db.QueryContext(ctx, `
		SELECT COALESCE(last_error,''), updated_at::text
		FROM arvis_stream_processing
		WHERE status IN ('failed','exhausted')
		ORDER BY updated_at DESC
		LIMIT 200
	`)
	if err != nil {
		return out
	}
	defer rows.Close()
	counts := map[string]int64{}
	latestCode := ""
	for rows.Next() {
		var raw, updatedAt string
		if rows.Scan(&raw, &updatedAt) != nil {
			continue
		}
		code := classifyArvisFailure(raw)
		counts[code]++
		if latestCode == "" {
			latestCode = code
		}
	}
	out["reason_counts"] = counts
	out["latest_error_code"] = latestCode
	return out
}

func classifyArvisFailure(raw string) string {
	text := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case text == "":
		return "unknown"
	case strings.Contains(text, "duplicate key") || strings.Contains(text, "23505") || strings.Contains(text, "unique constraint"):
		return "duplicate_write"
	case strings.Contains(text, "foreign key") || strings.Contains(text, "23503"):
		return "foreign_key"
	case strings.Contains(text, "null value") || strings.Contains(text, "23502") || strings.Contains(text, "check constraint") || strings.Contains(text, "23514"):
		return "schema_constraint"
	case strings.Contains(text, "does not exist") || strings.Contains(text, "undefined table") || strings.Contains(text, "undefined column") || strings.Contains(text, "42p01") || strings.Contains(text, "42703"):
		return "missing_schema"
	case strings.Contains(text, "invalid input syntax for type json") || strings.Contains(text, "unsupported value") || strings.Contains(text, "json"):
		return "json_encoding"
	case strings.Contains(text, "deadline exceeded") || strings.Contains(text, "timeout") || strings.Contains(text, "timed out"):
		return "timeout"
	case strings.Contains(text, "connection") || strings.Contains(text, "network") || strings.Contains(text, "broken pipe") || strings.Contains(text, "eof"):
		return "database_or_network"
	case strings.Contains(text, "insert arm verdict"):
		return "verdict_insert"
	case strings.Contains(text, "insert arm event"):
		return "event_insert"
	case strings.Contains(text, "check existing arm verdict"):
		return "idempotency_check"
	default:
		return "processing_error"
	}
}

func arvisModuleSourceHealth(ctx context.Context, db *sql.DB, moduleID string) map[string]any {
	out := map[string]any{
		"module_id":     moduleID,
		"events":        int64(0),
		"recent":        int64(0),
		"enriched":      int64(0),
		"last_event_at": "",
	}
	if db == nil || moduleID == "" {
		return out
	}
	count := func(key, query string) {
		var value int64
		if err := db.QueryRowContext(ctx, query, moduleID).Scan(&value); err == nil {
			out[key] = value
		}
	}
	count("events", `SELECT count(*) FROM security_radar_stream_events WHERE module_id=$1`)
	count("recent", `SELECT count(*) FROM security_radar_stream_events WHERE module_id=$1 AND created_at > now() - interval '15 minutes'`)
	count("enriched", `SELECT count(*) FROM security_radar_stream_events WHERE module_id=$1 AND evidence_quality='transaction_enriched_mint'`)
	var lastEvent string
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(max(created_at)::text,'') FROM security_radar_stream_events WHERE module_id=$1`, moduleID).Scan(&lastEvent); err == nil {
		out["last_event_at"] = lastEvent
	}
	return out
}
