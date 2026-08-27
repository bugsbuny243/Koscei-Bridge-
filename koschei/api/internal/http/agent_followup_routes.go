package http

import (
	"encoding/json"
	"net/http"
	"os"
)

type agentFollowupActionRequest struct {
	TenantID string `json:"tenant_id"`
	ID       int64  `json:"id"`
}

func registerTradePIAgentFollowupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/agents/admin/followups", tradePIAgentAdminFollowups)
	mux.HandleFunc("/api/agents/admin/followups/cancel", tradePIAgentAdminCancelFollowup)
	mux.HandleFunc("/api/agents/admin/followups/retry", tradePIAgentAdminRetryFollowup)
}

func tradePIAgentAdminFollowups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	status := r.URL.Query().Get("status")
	items, err := tradePIAgentService.AdminFollowups(r.Context(), tradePIAgentAdminTenant(r), status, tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "followups unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"items": items, "status": status})
}

func tradePIAgentAdminCancelFollowup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentFollowupActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.ID <= 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	tenantID := firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive")
	if err := tradePIAgentService.AdminCancelFollowup(r.Context(), tenantID, req.ID); err != nil {
		http.Error(w, "followup cancel failed", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "id": req.ID, "status": "cancelled"})
}

func tradePIAgentAdminRetryFollowup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentFollowupActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.ID <= 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	tenantID := firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive")
	if err := tradePIAgentService.AdminRetryFollowup(r.Context(), tenantID, req.ID); err != nil {
		http.Error(w, "followup retry failed", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "id": req.ID, "status": "pending"})
}
