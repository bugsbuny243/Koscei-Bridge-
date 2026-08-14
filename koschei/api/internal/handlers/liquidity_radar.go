package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"strings"
	"time"
)

type liquidityRadarRequest struct {
	PoolAddress       string   `json:"pool_address"`
	TokenMint         string   `json:"token_mint"`
	ReserveDropPct    float64  `json:"reserve_drop_pct"`
	RemovedLiquidity  float64  `json:"removed_liquidity_usd"`
	BlockDelay        int      `json:"block_delay"`
	TelegramWebhook   string   `json:"telegram_webhook"`
	DiscordWebhook    string   `json:"discord_webhook"`
	TwilioPhoneNumber string   `json:"twilio_phone_number"`
	WhitehatAddresses []string `json:"whitehat_addresses"`
}

type emergencyDispatchResult struct {
	EmergencyMode     bool     `json:"emergency_mode"`
	WhitehatAddresses []string `json:"whitehat_addresses"`
	TelegramSent      bool     `json:"telegram_sent"`
	DiscordSent       bool     `json:"discord_sent"`
	Errors            []string `json:"errors,omitempty"`
}

// LiquidityDrainAnalyze scores first-block rug-pull and liquidity drain risk.
// If risk is above 90%, Emergency Mode automatically notifies configured
// Telegram/Discord webhooks with the whitehat address list.
func (h *Handler) EmergencyAlert(w http.ResponseWriter, r *http.Request) {
	h.LiquidityDrainAnalyze(w, r)
}

func (h *Handler) LiquidityDrainAnalyze(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if _, err := h.requirePremiumOutput(claims.Sub); err != nil {
		writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
		return
	}

	var req liquidityRadarRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	if strings.TrimSpace(req.PoolAddress) == "" && strings.TrimSpace(req.TokenMint) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pool_or_token_required"})
		return
	}
	score := liquidityDrainScore(req)
	severity := "DÜŞÜK"
	if score >= 75 {
		severity = "KRİTİK"
	} else if score >= 45 {
		severity = "YÜKSEK"
	}
	lossPrevented := math.Round(req.RemovedLiquidity*float64(score)/100*100) / 100
	emergency := dispatchEmergencyLiquidityAlert(r.Context(), req, score, severity, lossPrevented)
	alertPayload, _ := json.Marshal(map[string]any{"emergency": emergency, "whitehat_addresses": emergency.WhitehatAddresses})
	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO liquidity_drain_alerts (pool_address, token_mint, severity, risk_score, removed_liquidity_usd, loss_prevented_usd, telegram_queued, sms_queued, alert_payload, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,now())`, req.PoolAddress, req.TokenMint, severity, score, req.RemovedLiquidity, lossPrevented, emergency.TelegramSent, req.TwilioPhoneNumber != "", string(alertPayload)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	if err := h.applyCreditChargeTxWithReason(tx, claims.Sub, claims.Email, "liquidity_radar"); err != nil {
		writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "risk_score": score, "severity": severity, "liquidity_loss_prevented_usd": lossPrevented, "telegram_queued": emergency.TelegramSent, "discord_queued": emergency.DiscordSent, "sms_queued": req.TwilioPhoneNumber != "", "emergency": emergency, "message": "Likidite boşaltma radarı alarmı üretildi."})
}

func liquidityDrainScore(req liquidityRadarRequest) int {
	score := 10
	if req.ReserveDropPct >= 20 {
		score += 30
	}
	if req.ReserveDropPct >= 50 {
		score += 30
	}
	if req.RemovedLiquidity >= 50_000 {
		score += 20
	}
	if req.BlockDelay <= 1 {
		score += 10
	}
	if score > 100 {
		return 100
	}
	return score
}

func dispatchEmergencyLiquidityAlert(ctx context.Context, req liquidityRadarRequest, score int, severity string, lossPrevented float64) emergencyDispatchResult {
	result := emergencyDispatchResult{EmergencyMode: score > 90, WhitehatAddresses: whitehatAddresses(req.WhitehatAddresses)}
	if !result.EmergencyMode {
		return result
	}
	message := fmt.Sprintf("🚨 Koschei Emergency Mode: liquidity drain risk %d%% (%s). Pool: %s Token: %s Removed: $%.2f Protected estimate: $%.2f Whitehats: %s", score, severity, firstNonEmpty(req.PoolAddress, "unknown"), firstNonEmpty(req.TokenMint, "unknown"), req.RemovedLiquidity, lossPrevented, strings.Join(result.WhitehatAddresses, ", "))
	// Webhook destinations are operator configuration, never request input. The
	// request fields remain in the JSON contract only for backward compatibility.
	telegramURL := strings.TrimSpace(os.Getenv("TELEGRAM_WEBHOOK_URL"))
	if telegramURL != "" {
		telegramPayload := map[string]any{"text": message}
		if chatID := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")); chatID != "" {
			telegramPayload["chat_id"] = chatID
		}
		if err := postWebhook(ctx, telegramURL, telegramPayload); err != nil {
			result.Errors = append(result.Errors, "telegram: "+err.Error())
		} else {
			result.TelegramSent = true
		}
	}
	discordURL := strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK_URL"))
	if discordURL != "" {
		if err := postWebhook(ctx, discordURL, map[string]any{"content": message}); err != nil {
			result.Errors = append(result.Errors, "discord: "+err.Error())
		} else {
			result.DiscordSent = true
		}
	}
	return result
}

func whitehatAddresses(input []string) []string {
	items := append([]string{}, input...)
	if envList := strings.TrimSpace(os.Getenv("WHITEHAT_ALERT_ADDRESSES")); envList != "" {
		items = append(items, strings.Split(envList, ",")...)
	}
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		addr := strings.TrimSpace(item)
		if addr == "" || seen[strings.ToLower(addr)] {
			continue
		}
		seen[strings.ToLower(addr)] = true
		out = append(out, addr)
	}
	return out
}

func postWebhook(ctx context.Context, url string, payload map[string]any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 6 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", res.Status)
	}
	return nil
}
