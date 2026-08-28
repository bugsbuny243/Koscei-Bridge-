package http

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"koschei/api/internal/agents"
)

type agentTenantSettingsRequest struct {
	TenantID             string `json:"tenant_id"`
	DisplayName          string `json:"display_name"`
	Vertical             string `json:"vertical"`
	Timezone             string `json:"timezone"`
	Language             string `json:"language"`
	AssignmentSLAMinutes int    `json:"assignment_sla_minutes"`
	FollowupDelayMinutes int    `json:"followup_delay_minutes"`
	Status               string `json:"status"`
}

type agentTenantOnboardingRequest struct {
	DisplayName          string `json:"display_name"`
	Vertical             string `json:"vertical"`
	Timezone             string `json:"timezone"`
	Language             string `json:"language"`
	AllowedOrigin        string `json:"allowed_origin"`
	Label                string `json:"label"`
	AssignmentSLAMinutes int    `json:"assignment_sla_minutes"`
	FollowupDelayMinutes int    `json:"followup_delay_minutes"`
}

func registerTradePIAgentTenantRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/agents/admin/tenant", tradePIAgentAdminTenantSettings)
	mux.HandleFunc("/api/agents/admin/onboard", method("POST", tradePIAgentAdminOnboardTenant))
}

func tradePIAgentAdminTenantSettings(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		settings, err := tradePIAgentService.AdminTenantSettings(r.Context(), tradePIAgentAdminTenant(r))
		if err != nil {
			http.Error(w, "tenant settings unavailable", http.StatusServiceUnavailable)
			return
		}
		writeTradePIAgentJSON(w, settings)
	case http.MethodPost:
		var req agentTenantSettingsRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		settings := agents.TenantSettings{
			TenantID: firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive"),
			DisplayName: req.DisplayName,
			Vertical: req.Vertical,
			Timezone: req.Timezone,
			Language: req.Language,
			AssignmentSLAMinutes: req.AssignmentSLAMinutes,
			FollowupDelayMinutes: req.FollowupDelayMinutes,
			Status: req.Status,
		}
		if err := tradePIAgentService.AdminUpsertTenantSettings(r.Context(), settings); err != nil {
			http.Error(w, "tenant settings rejected", http.StatusConflict)
			return
		}
		writeTradePIAgentJSON(w, map[string]any{"ok": true, "tenant_id": settings.TenantID})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func tradePIAgentAdminOnboardTenant(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentTenantOnboardingRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.DisplayName) == "" || strings.TrimSpace(req.AllowedOrigin) == "" {
		http.Error(w, "display_name and allowed_origin are required", http.StatusBadRequest)
		return
	}
	result, err := tradePIAgentService.AdminOnboardWebTenant(
		r.Context(),
		req.DisplayName,
		req.Vertical,
		req.Timezone,
		req.Language,
		req.AllowedOrigin,
		req.Label,
		req.AssignmentSLAMinutes,
		req.FollowupDelayMinutes,
	)
	if err != nil {
		http.Error(w, "tenant onboarding rejected", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, result)
}
