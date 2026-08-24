package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/defense"
)

type defenseSentinelRequest struct {
	Action              string `json:"action"`
	MonitorRef          string `json:"monitor_ref"`
	ProgramID           string `json:"program_id"`
	Network             string `json:"network"`
	ManifestArtifactRef string `json:"manifest_artifact_ref"`
	IntervalSeconds     int    `json:"interval_seconds"`
}

// OwnerDefenseSentinel manages read-only Solana program deployment monitors.
func (h *Handler) OwnerDefenseSentinel(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		view := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("view")))
		if view == "events" {
			events, err := defense.ListProgramChangeEvents(r.Context(), h.DB, r.URL.Query().Get("program_id"), limit)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "program_change_event_list_failed"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "events": events, "verdict_authority": false})
			return
		}
		monitors, err := defense.ListProgramMonitors(r.Context(), h.DB, r.URL.Query().Get("active") == "true", limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "program_monitor_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "monitors": monitors, "read_only_rpc": true})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !envBool("KOSCHEI_DEFENSE_SENTINEL_MANAGEMENT_ENABLED", false) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "defense_sentinel_management_disabled"})
		return
	}
	var input defenseSentinelRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_program_sentinel_request"})
		return
	}
	switch strings.ToLower(strings.TrimSpace(input.Action)) {
	case "watch":
		monitor, err := defense.UpsertProgramMonitor(r.Context(), h.DB, defense.ProgramMonitorInput{
			ProgramID:           input.ProgramID,
			Network:             input.Network,
			ManifestArtifactRef: input.ManifestArtifactRef,
			IntervalSeconds:     input.IntervalSeconds,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "program_monitor_rejected", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "monitor": monitor, "execution_service": "railway-defense-sentinel"})
	case "disable":
		monitor, err := defense.DisableProgramMonitor(r.Context(), h.DB, input.MonitorRef)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "program_monitor_disable_failed", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "monitor": monitor})
	case "check_now":
		if h.SolanaRPC == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "solana_rpc_unavailable"})
			return
		}
		monitor, err := defense.GetProgramMonitor(r.Context(), h.DB, strings.TrimSpace(input.MonitorRef))
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "program_monitor_not_found"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		result, err := defense.CheckProgramMonitor(ctx, h.DB, h.SolanaRPC, monitor)
		if err != nil {
			_ = defense.FailProgramMonitorCheck(context.Background(), h.DB, monitor, "", err)
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "program_monitor_check_failed", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                       true,
			"check":                    result,
			"read_only_rpc":            true,
			"mainnet_transaction_sent": false,
			"verdict_authority":        false,
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_program_sentinel_action"})
	}
}
