package http

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/agents"
)

type agentChannelCreateRequest struct {
	TenantID          string `json:"tenant_id"`
	Channel           string `json:"channel"`
	ProviderAccountID string `json:"provider_account_id"`
	AllowedOrigin     string `json:"allowed_origin"`
	Label             string `json:"label"`
}

type agentChannelStatusRequest struct {
	TenantID string `json:"tenant_id"`
	ID       int64  `json:"id"`
	Status   string `json:"status"`
}

type publicAgentChatRequest struct {
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name"`
	Text        string `json:"text"`
}

func registerTradePIAgentChannelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/agents/chat", tradePIAgentPublicChat)
	mux.HandleFunc("/api/agents/admin/channels", method("GET", tradePIAgentAdminChannels))
	mux.HandleFunc("/api/agents/admin/channels/create", method("POST", tradePIAgentAdminCreateChannel))
	mux.HandleFunc("/api/agents/admin/channels/status", method("POST", tradePIAgentAdminChannelStatus))
}

func tradePIAgentPublicChat(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.Header.Get("X-TradePI-Agent-Key"))
	if key == "" {
		key = strings.TrimSpace(r.URL.Query().Get("key"))
	}
	account, err := tradePIAgentService.ResolveChannelAccount(r.Context(), agents.ChannelWeb, key, "")
	if err != nil {
		http.Error(w, "unknown or disabled agent key", http.StatusUnauthorized)
		return
	}

	origin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
	allowed := strings.TrimRight(strings.TrimSpace(account.AllowedOrigin), "/")
	if allowed != "" && origin != allowed {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-TradePI-Agent-Key")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req publicAgentChatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.Text = strings.TrimSpace(req.Text)
	if req.UserID == "" || req.Text == "" || len(req.UserID) > 200 || len(req.Text) > 8000 {
		http.Error(w, "user_id and text are required", http.StatusBadRequest)
		return
	}

	msg := agents.Message{
		TenantID:         account.TenantID,
		Channel:          agents.ChannelWeb,
		ChannelAccountID: account.ID,
		ChannelUserID:    req.UserID,
		DisplayName:      req.DisplayName,
		Text:             req.Text,
		ReceivedAt:       time.Now().UTC(),
	}
	result := tradePIAgentService.Handle(r.Context(), msg)
	tradePIAgentService.RecordOutbound(r.Context(), msg, result.Reply)
	writeTradePIAgentJSON(w, map[string]any{
		"reply": result.Reply,
		"stage": result.Lead.Stage,
		"score": result.Lead.Score,
		"handoff_requested": result.Handoff != nil,
		"appointment_requested": result.Appointment != nil,
	})
}

func tradePIAgentAdminChannels(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	items, err := tradePIAgentService.AdminChannelAccounts(r.Context(), tradePIAgentAdminTenant(r), tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "channel accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"items": items})
}

func tradePIAgentAdminCreateChannel(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentChannelCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	account, err := tradePIAgentService.AdminCreateChannelAccount(
		r.Context(),
		firstNonEmpty(req.TenantID, tradePIAgentAdminTenant(r)),
		req.Channel,
		req.ProviderAccountID,
		req.AllowedOrigin,
		req.Label,
	)
	if err != nil {
		http.Error(w, "channel account rejected", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, account)
}

func tradePIAgentAdminChannelStatus(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentChannelStatusRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.ID <= 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := tradePIAgentService.AdminSetChannelAccountStatus(r.Context(), firstNonEmpty(req.TenantID, tradePIAgentAdminTenant(r)), req.ID, req.Status); err != nil {
		http.Error(w, "channel account update failed", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "id": req.ID, "status": strings.ToLower(strings.TrimSpace(req.Status))})
}
