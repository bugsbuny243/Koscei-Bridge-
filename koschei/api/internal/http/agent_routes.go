package http

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/agents"
)

var tradePIAgentService = agents.NewService()

type agentDemoRequest struct {
	TenantID    string `json:"tenant_id"`
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name"`
	Text        string `json:"text"`
}

type agentAdminActionRequest struct {
	TenantID         string `json:"tenant_id"`
	ID               int64  `json:"id"`
	Status           string `json:"status"`
	ScheduledFor     string `json:"scheduled_for"`
	CalendarProvider string `json:"calendar_provider"`
	CalendarEventID  string `json:"calendar_event_id"`
}

type agentAdminLeadAssignRequest struct {
	TenantID      string `json:"tenant_id"`
	Channel       string `json:"channel"`
	ExternalID    string `json:"external_id"`
	OwnerID       string `json:"owner_id"`
	CRMExternalID string `json:"crm_external_id"`
}

type agentAdminRevenueRequest struct {
	TenantID    string `json:"tenant_id"`
	Channel     string `json:"channel"`
	ExternalID  string `json:"external_id"`
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
	Source      string `json:"source"`
	EvidenceRef string `json:"evidence_ref"`
	OccurredAt  string `json:"occurred_at"`
}

func registerTradePIAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/agents/health", method("GET", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                  true,
			"product":             "tradepi-ai-agents",
			"mode":                "single-service",
			"persistence_enabled": tradePIAgentService.PersistenceEnabled(),
			"persistence_ready":   tradePIAgentService.PersistenceReady(r.Context()),
			"telegram_enabled":    strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")) != "",
			"llm_enabled":         tradePIAgentService.LLMEnabled(),
			"admin_configured":    strings.TrimSpace(os.Getenv("TRADEPI_AGENT_ADMIN_TOKEN")) != "",
		})
	}))
	mux.HandleFunc("/api/agents/demo", method("POST", tradePIAgentDemo))
	mux.HandleFunc("/webhooks/telegram", method("POST", tradePITelegramWebhook))
	mux.HandleFunc("/api/agents/admin/queue", method("GET", tradePIAgentAdminQueue))
	mux.HandleFunc("/api/agents/admin/leads", method("GET", tradePIAgentAdminLeads))
	mux.HandleFunc("/api/agents/admin/leads/assign", method("POST", tradePIAgentAdminAssignLead))
	mux.HandleFunc("/api/agents/admin/handoffs", method("GET", tradePIAgentAdminHandoffs))
	mux.HandleFunc("/api/agents/admin/handoffs/resolve", method("POST", tradePIAgentAdminResolveHandoff))
	mux.HandleFunc("/api/agents/admin/appointments", method("GET", tradePIAgentAdminAppointments))
	mux.HandleFunc("/api/agents/admin/appointments/update", method("POST", tradePIAgentAdminUpdateAppointment))
	mux.HandleFunc("/api/agents/admin/revenue", method("GET", tradePIAgentAdminRevenue))
	mux.HandleFunc("/api/agents/admin/revenue/record", method("POST", tradePIAgentAdminRecordRevenue))
}

func tradePIAgentAdminAuthorized(w http.ResponseWriter, r *http.Request) bool {
	expected := strings.TrimSpace(os.Getenv("TRADEPI_AGENT_ADMIN_TOKEN"))
	if expected == "" {
		http.Error(w, "agent admin is not configured", http.StatusServiceUnavailable)
		return false
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func tradePIAgentAdminTenant(r *http.Request) string {
	return firstNonEmpty(r.URL.Query().Get("tenant_id"), os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive")
}

func tradePIAgentAdminLimit(r *http.Request) int {
	value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	if err != nil || value <= 0 {
		return 25
	}
	if value > 100 {
		return 100
	}
	return value
}

func tradePIAgentAdminQueue(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	queue, err := tradePIAgentService.AdminQueue(r.Context(), tradePIAgentAdminTenant(r), tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "agent queue unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, queue)
}

func tradePIAgentAdminLeads(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	items, err := tradePIAgentService.AdminLeads(r.Context(), tradePIAgentAdminTenant(r), tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "agent leads unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"items": items})
}

func tradePIAgentAdminAssignLead(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentAdminLeadAssignRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	tenantID := firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive")
	if strings.TrimSpace(req.Channel) == "" || strings.TrimSpace(req.ExternalID) == "" || strings.TrimSpace(req.OwnerID) == "" {
		http.Error(w, "channel, external_id and owner_id are required", http.StatusBadRequest)
		return
	}
	if err := tradePIAgentService.AdminAssignLead(r.Context(), tenantID, req.Channel, req.ExternalID, req.OwnerID, req.CRMExternalID); err != nil {
		http.Error(w, "lead assignment failed", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "external_id": req.ExternalID, "owner_id": req.OwnerID})
}

func tradePIAgentAdminHandoffs(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	status := firstNonEmpty(r.URL.Query().Get("status"), "requested")
	items, err := tradePIAgentService.AdminHandoffs(r.Context(), tradePIAgentAdminTenant(r), status, tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "agent handoffs unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"items": items})
}

func tradePIAgentAdminResolveHandoff(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentAdminActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.ID <= 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	tenantID := firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive")
	if err := tradePIAgentService.AdminResolveHandoff(r.Context(), tenantID, req.ID); err != nil {
		http.Error(w, "handoff update failed", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "id": req.ID, "status": "resolved"})
}

func tradePIAgentAdminAppointments(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	status := firstNonEmpty(r.URL.Query().Get("status"), "requested")
	items, err := tradePIAgentService.AdminAppointments(r.Context(), tradePIAgentAdminTenant(r), status, tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "agent appointments unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"items": items})
}

func tradePIAgentAdminUpdateAppointment(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentAdminActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.ID <= 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	var scheduledFor *time.Time
	if status == "confirmed" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ScheduledFor))
		if err != nil {
			http.Error(w, "scheduled_for must be RFC3339 for confirmed appointments", http.StatusBadRequest)
			return
		}
		parsed = parsed.UTC()
		scheduledFor = &parsed
	}
	tenantID := firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive")
	if err := tradePIAgentService.AdminUpdateAppointmentCalendar(r.Context(), tenantID, req.ID, status, scheduledFor, req.CalendarProvider, req.CalendarEventID); err != nil {
		http.Error(w, "appointment update failed", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "id": req.ID, "status": status, "scheduled_for": scheduledFor, "calendar_provider": req.CalendarProvider, "calendar_event_id": req.CalendarEventID})
}

func tradePIAgentAdminRevenue(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	tenantID := tradePIAgentAdminTenant(r)
	summary, err := tradePIAgentService.AdminRevenueSummary(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "revenue summary unavailable", http.StatusServiceUnavailable)
		return
	}
	items, err := tradePIAgentService.AdminRevenueEvents(r.Context(), tenantID, tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "revenue events unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"summary": summary, "items": items})
}

func tradePIAgentAdminRecordRevenue(w http.ResponseWriter, r *http.Request) {
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentAdminRevenueRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	occurredAt, err := time.Parse(time.RFC3339, strings.TrimSpace(req.OccurredAt))
	if err != nil {
		http.Error(w, "occurred_at must be RFC3339", http.StatusBadRequest)
		return
	}
	event := agents.AdminRevenueEvent{
		TenantID: firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive"),
		Channel:  req.Channel, ExternalID: req.ExternalID, AmountMinor: req.AmountMinor,
		Currency: req.Currency, Source: req.Source, EvidenceRef: req.EvidenceRef, OccurredAt: occurredAt.UTC(),
	}
	if err := tradePIAgentService.AdminRecordRevenue(r.Context(), event); err != nil {
		http.Error(w, "revenue record rejected", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "external_id": req.ExternalID, "amount_minor": req.AmountMinor, "currency": strings.ToUpper(strings.TrimSpace(req.Currency))})
}

func writeTradePIAgentJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func tradePIAgentDemo(w http.ResponseWriter, r *http.Request) {
	var req agentDemoRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		http.Error(w, "text is required", http.StatusBadRequest)
		return
	}
	// This endpoint is an intentionally isolated public sandbox. Customer tenants
	// are resolved only through channel-account routing, never from request JSON.
	req.TenantID = "demo-automotive"
	if strings.TrimSpace(req.UserID) == "" {
		req.UserID = "demo-user"
	}
	msg := agents.Message{
		TenantID: req.TenantID, Channel: agents.ChannelWeb, ChannelUserID: req.UserID,
		DisplayName: req.DisplayName, Text: req.Text, ReceivedAt: time.Now().UTC(),
	}
	result := tradePIAgentService.Handle(r.Context(), msg)
	tradePIAgentService.RecordOutbound(r.Context(), msg, result.Reply)
	writeTradePIAgentJSON(w, result)
}

func tradePITelegramWebhook(w http.ResponseWriter, r *http.Request) {
	secret := strings.TrimSpace(os.Getenv("TELEGRAM_WEBHOOK_SECRET"))
	if secret != "" && r.Header.Get("X-Telegram-Bot-Api-Secret-Token") != secret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var payload struct {
		UpdateID int64 `json:"update_id"`
		Message  *struct {
			MessageID int64  `json:"message_id"`
			Date      int64  `json:"date"`
			Text      string `json:"text"`
			Chat      struct {
				ID int64 `json:"id"`
			} `json:"chat"`
			From *struct {
				ID        int64  `json:"id"`
				FirstName string `json:"first_name"`
				LastName  string `json:"last_name"`
			} `json:"from"`
		} `json:"message"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if payload.Message == nil || payload.Message.From == nil || strings.TrimSpace(payload.Message.Text) == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	name := strings.TrimSpace(payload.Message.From.FirstName + " " + payload.Message.From.LastName)
	msg := agents.Message{
		TenantID: firstNonEmpty(os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive"),
		Channel:  agents.ChannelTelegram, ChannelChatID: int64String(payload.Message.Chat.ID),
		ChannelUserID: int64String(payload.Message.From.ID), DisplayName: name,
		Text: payload.Message.Text, ReceivedAt: time.Unix(payload.Message.Date, 0).UTC(),
	}
	result := tradePIAgentService.Handle(r.Context(), msg)
	outbound := "disabled"
	if token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")); token != "" {
		if err := sendTelegramText(r, token, payload.Message.Chat.ID, result.Reply); err != nil {
			outbound = "failed"
		} else {
			outbound = "sent"
			tradePIAgentService.RecordOutbound(r.Context(), msg, result.Reply)
		}
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "outbound": outbound, "reply": result.Reply, "lead": result.Lead, "vehicles": result.Vehicles})
}

func sendTelegramText(r *http.Request, token string, chatID int64, text string) error {
	body, err := json.Marshal(map[string]any{"chat_id": chatID, "text": text})
	if err != nil {
		return err
	}
	endpoint := "https://api.telegram.org/bot" + token + "/sendMessage"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram send status %d", resp.StatusCode)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func int64String(v int64) string { return fmt.Sprintf("%d", v) }
