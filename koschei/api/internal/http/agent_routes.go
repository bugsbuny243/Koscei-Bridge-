package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

func registerTradePIAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/agents/health", method("GET", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"product": "tradepi-ai-agents",
			"mode": "single-service",
			"persistence_enabled": tradePIAgentService.PersistenceEnabled(),
			"telegram_enabled": strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")) != "",
		})
	}))
	mux.HandleFunc("/api/agents/demo", method("POST", tradePIAgentDemo))
	mux.HandleFunc("/webhooks/telegram", method("POST", tradePITelegramWebhook))
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
	if strings.TrimSpace(req.TenantID) == "" { req.TenantID = "demo-automotive" }
	if strings.TrimSpace(req.UserID) == "" { req.UserID = "demo-user" }
	msg := agents.Message{
		TenantID: req.TenantID,
		Channel: agents.ChannelWeb,
		ChannelUserID: req.UserID,
		DisplayName: req.DisplayName,
		Text: req.Text,
		ReceivedAt: time.Now().UTC(),
	}
	result := tradePIAgentService.Handle(r.Context(), msg)
	tradePIAgentService.RecordOutbound(r.Context(), msg, result.Reply)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func tradePITelegramWebhook(w http.ResponseWriter, r *http.Request) {
	secret := strings.TrimSpace(os.Getenv("TELEGRAM_WEBHOOK_SECRET"))
	if secret != "" && r.Header.Get("X-Telegram-Bot-Api-Secret-Token") != secret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var payload struct {
		UpdateID int64 `json:"update_id"`
		Message *struct {
			MessageID int64 `json:"message_id"`
			Date int64 `json:"date"`
			Text string `json:"text"`
			Chat struct { ID int64 `json:"id"` } `json:"chat"`
			From *struct {
				ID int64 `json:"id"`
				FirstName string `json:"first_name"`
				LastName string `json:"last_name"`
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
		Channel: agents.ChannelTelegram,
		ChannelChatID: int64String(payload.Message.Chat.ID),
		ChannelUserID: int64String(payload.Message.From.ID),
		DisplayName: name,
		Text: payload.Message.Text,
		ReceivedAt: time.Unix(payload.Message.Date, 0).UTC(),
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "outbound": outbound, "reply": result.Reply, "lead": result.Lead, "vehicles": result.Vehicles})
}

func sendTelegramText(r *http.Request, token string, chatID int64, text string) error {
	body, err := json.Marshal(map[string]any{"chat_id": chatID, "text": text})
	if err != nil { return err }
	endpoint := "https://api.telegram.org/bot" + token + "/sendMessage"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { return fmt.Errorf("telegram send status %d", resp.StatusCode) }
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" { return strings.TrimSpace(value) }
	}
	return ""
}

func int64String(v int64) string { return fmt.Sprintf("%d", v) }
