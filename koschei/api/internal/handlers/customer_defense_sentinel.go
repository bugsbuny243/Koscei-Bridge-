package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/defense"
)

// CustomerDefenseSentinel exposes the read-only Program Sentinel to registered
// users and API accounts. Owner routes remain available for operations, but are
// not the product's only access path.
func (h *Handler) CustomerDefenseSentinel(w http.ResponseWriter, r *http.Request) {
	subject := dossierRequester(r)
	if subject == "owner" && !dossierOwnerCredentialPresent(r) {
		writeAPIError(w, http.StatusUnauthorized, APICodeUnauthorized, "Authenticated user or API key is required")
		return
	}
	if r.Method == http.MethodGet {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListSubscribedProgramMonitors(r.Context(), h.DB, subject, r.URL.Query().Get("active") == "true", limit)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "program_monitor_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "monitors": items, "read_only_rpc": true, "subscriber": subject})
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
		monitor, err := defense.SubscribeProgramMonitor(r.Context(), h.DB, defense.ProgramMonitorInput{
			ProgramID: input.ProgramID, Network: input.Network, ManifestArtifactRef: input.ManifestArtifactRef, IntervalSeconds: input.IntervalSeconds,
		}, subject)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "program_monitor_rejected", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "monitor": monitor, "read_only_rpc": true})
	case "disable":
		monitor, err := defense.UnsubscribeProgramMonitor(r.Context(), h.DB, input.MonitorRef, subject)
		if err != nil {
			status := http.StatusBadRequest
			if err == sql.ErrNoRows {
				status = http.StatusNotFound
			}
			writeJSON(w, status, map[string]any{"error": "program_monitor_unsubscribe_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "monitor": monitor, "subscription_active": false})
	case "check_now":
		if h.SolanaRPC == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "solana_rpc_unavailable"})
			return
		}
		monitor, err := defense.GetSubscribedProgramMonitor(r.Context(), h.DB, input.MonitorRef, subject)
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
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "check": result, "read_only_rpc": true, "mainnet_transaction_sent": false, "verdict_authority": false})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_program_sentinel_action"})
	}
}
