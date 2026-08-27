package http

import (
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
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = "demo-automotive"
	}
	if strings.TrimSpace(req.UserID) == "" {
		req.UserID = "demo-user"
	}
	result := tradePIAgentService.Handle(r.Context(), agents.Message{
		TenantID:      req.TenantID,
		Channel:       agents.ChannelWeb,
		ChannelUserID: req.UserID,
		DisplayName:   req.DisplayName,
		Text:          req.Text,
		ReceivedAt:    time.Now().UTC(),
	})
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
	result := tradePIAgentService.Handle(r.Context(), agents.Message{
		TenantID:      firstNonEmpty(os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive"),
		Channel:       agents.ChannelTelegram,
		ChannelChatID: int64String(payload.Message.Chat.ID),
		ChannelUserID: int64String(payload.Message.From.ID),
		DisplayName:   name,
		Text:          payload.Message.Text,
		ReceivedAt:    time.Unix(payload.Message.Date, 0).UTC(),
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "reply": result.Reply, "lead": result.Lead, "vehicles": result.Vehicles})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func int64String(v int64) string {
	return fmt.Sprintf("%d", v)
}
