package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"koschei/api/internal/agents"
)

type agentPilotLeadRequest struct {
	BusinessName    string `json:"business_name"`
	ContactName     string `json:"contact_name"`
	Email           string `json:"email"`
	Phone           string `json:"phone"`
	Website         string `json:"website"`
	Vertical        string `json:"vertical"`
	MonthlyLeadBand string `json:"monthly_lead_band"`
	Message         string `json:"message"`
	Company         string `json:"company"`
}

type agentPilotStatusRequest struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
}

func registerTradePIAgentPilotRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/agents/pilot", method("POST", tradePIAgentPilotApply))
	mux.HandleFunc("/api/agents/admin/pilots", method("GET", tradePIAgentAdminPilots))
	mux.HandleFunc("/api/agents/admin/pilots/status", method("POST", tradePIAgentAdminPilotStatus))
}

func tradePIAgentPilotApply(w http.ResponseWriter, r *http.Request) {
	var req agentPilotLeadRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// Hidden honeypot. Legitimate clients leave it empty.
	if strings.TrimSpace(req.Company) != "" {
		writeTradePIAgentJSON(w, map[string]any{"ok": true})
		return
	}
	lead := agents.PilotLead{
		BusinessName:    req.BusinessName,
		ContactName:     req.ContactName,
		Email:           req.Email,
		Phone:           req.Phone,
		Website:         req.Website,
		Vertical:        req.Vertical,
		MonthlyLeadBand: req.MonthlyLeadBand,
		Message:         req.Message,
		Source:          "agents-page",
	}
	if err := tradePIAgentService.SubmitPilotLead(r.Context(), lead); err != nil {
		http.Error(w, "application rejected", http.StatusBadRequest)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "status": "received"})
}

func tradePIAgentAdminPilots(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	status := firstNonEmpty(r.URL.Query().Get("status"), "new")
	items, err := tradePIAgentService.AdminPilotLeads(r.Context(), status, tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "pilot leads unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"items": items})
}

func tradePIAgentAdminPilotStatus(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentPilotStatusRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.ID <= 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := tradePIAgentService.AdminUpdatePilotLead(r.Context(), req.ID, req.Status); err != nil {
		http.Error(w, "pilot lead update failed", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "id": req.ID, "status": strings.ToLower(strings.TrimSpace(req.Status))})
}
