package http

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

type agentEscalationActionRequest struct {
	TenantID string `json:"tenant_id"`
	ID       int64  `json:"id"`
	Status   string `json:"status"`
}

func registerTradePIAgentEscalationRoutes(mux *http.ServeMux) {
	tradePIAgentService.StartEscalationWorker()
	tradePIAgentService.StartOperatorNotificationWorker()
	mux.HandleFunc("/api/agents/admin/escalations", method("GET", tradePIAgentAdminEscalations))
	mux.HandleFunc("/api/agents/admin/escalations/update", method("POST", tradePIAgentAdminUpdateEscalation))
}

func tradePIAgentAdminEscalations(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	status := firstNonEmpty(r.URL.Query().Get("status"), "open")
	items, err := tradePIAgentService.AdminEscalations(r.Context(), tradePIAgentAdminTenant(r), status, tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "escalations unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"items": items})
}

func tradePIAgentAdminUpdateEscalation(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentEscalationActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.ID <= 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	tenantID := firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive")
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if err := tradePIAgentService.AdminUpdateEscalation(r.Context(), tenantID, req.ID, status); err != nil {
		http.Error(w, "escalation update failed", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "id": req.ID, "status": status, "source": "operator"})
}
