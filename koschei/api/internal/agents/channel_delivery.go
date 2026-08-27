package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var graphVersionPattern = regexp.MustCompile(`^v[0-9]+(?:\.[0-9]+)?$`)

func WhatsAppOutboundEnabled() bool {
	return strings.TrimSpace(os.Getenv("WHATSAPP_ACCESS_TOKEN")) != "" &&
		strings.TrimSpace(os.Getenv("WHATSAPP_PHONE_NUMBER_ID")) != "" &&
		graphVersionPattern.MatchString(strings.TrimSpace(os.Getenv("WHATSAPP_GRAPH_VERSION")))
}

func SendWhatsAppText(ctx context.Context, to, text string) error {
	if !WhatsAppOutboundEnabled() { return fmt.Errorf("whatsapp outbound not configured") }
	token := strings.TrimSpace(os.Getenv("WHATSAPP_ACCESS_TOKEN"))
	phoneID := strings.TrimSpace(os.Getenv("WHATSAPP_PHONE_NUMBER_ID"))
	version := strings.TrimSpace(os.Getenv("WHATSAPP_GRAPH_VERSION"))
	payload, err := json.Marshal(map[string]any{
		"messaging_product": "whatsapp",
		"to": strings.TrimSpace(to),
		"type": "text",
		"text": map[string]string{"body": text},
	})
	if err != nil { return err }
	endpoint := fmt.Sprintf("https://graph.facebook.com/%s/%s/messages", version, phoneID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { return fmt.Errorf("whatsapp send status %d", resp.StatusCode) }
	return nil
}

func SendTelegramText(ctx context.Context, chatID, text string) error {
	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	if token == "" { return fmt.Errorf("telegram outbound not configured") }
	payload, err := json.Marshal(map[string]any{"chat_id": strings.TrimSpace(chatID), "text": text})
	if err != nil { return err }
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewReader(payload))
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { return fmt.Errorf("telegram send status %d", resp.StatusCode) }
	return nil
}
