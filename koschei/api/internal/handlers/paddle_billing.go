package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const (
	paddleWebhookBodyLimit       = int64(1 << 20)
	paddleWebhookTimestampWindow = 30 * time.Second
	paddleAPITimeout             = 12 * time.Second
)

type paddleCheckoutRequest struct {
	Plan string `json:"plan"`
}

type paddleCreateTransactionResponse struct {
	Data struct {
		ID       string `json:"id"`
		Checkout struct {
			URL string `json:"url"`
		} `json:"checkout"`
	} `json:"data"`
	Error any `json:"error"`
}

type paddleWebhookEnvelope struct {
	EventID        string          `json:"event_id"`
	NotificationID string          `json:"notification_id"`
	EventType      string          `json:"event_type"`
	OccurredAt     string          `json:"occurred_at"`
	Data           json.RawMessage `json:"data"`
}

type paddleTransactionEvent struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	CustomData  map[string]any `json:"custom_data"`
	Items       []struct {
		Price struct {
			ID string `json:"id"`
		} `json:"price"`
		PriceID string `json:"price_id"`
	} `json:"items"`
	BillingPeriod *struct {
		EndsAt string `json:"ends_at"`
	} `json:"billing_period"`
}

func (h *Handler) PaddleCheckout(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_unavailable"})
		return
	}
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var input paddleCheckoutRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	plan := normalizePackageID(input.Plan)
	if planTierRank(plan) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_plan"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(normalizedClaimEmail(claims)))
	if email == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "verified_email_required"})
		return
	}

	cfg := services.LoadPaddleConfigFromEnv()
	priceID := strings.TrimSpace(cfg.PriceID(plan))
	if !cfg.APIKeyConfigured || priceID == "" || strings.TrimSpace(cfg.CheckoutURL) == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "paddle_checkout_not_configured", "plan": plan,
		})
		return
	}
	if cfg.APIKeyEnvironment != "unknown" && cfg.APIKeyEnvironment != cfg.Environment {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "paddle_environment_mismatch"})
		return
	}

	payload := map[string]any{
		"items": []map[string]any{{"price_id": priceID, "quantity": 1}},
		"custom_data": map[string]string{
			"koschei_auth_subject": strings.TrimSpace(claims.Sub),
			"koschei_email":        email,
			"koschei_plan":         plan,
		},
		"checkout": map[string]string{"url": strings.TrimSpace(cfg.CheckoutURL)},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "checkout_payload_failed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), paddleAPITimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.APIBaseURL(), "/")+"/transactions", bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "checkout_request_failed"})
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Paddle-Version", "1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: paddleAPITimeout}).Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "paddle_unavailable"})
		return
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, paddleWebhookBodyLimit))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "paddle_response_unreadable"})
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "paddle_checkout_failed", "provider_status": resp.StatusCode})
		return
	}
	var created paddleCreateTransactionResponse
	if err := json.Unmarshal(responseBody, &created); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "paddle_response_invalid"})
		return
	}
	transactionID := strings.TrimSpace(created.Data.ID)
	checkoutURL := strings.TrimSpace(created.Data.Checkout.URL)
	if transactionID == "" || checkoutURL == "" || !strings.HasPrefix(strings.ToLower(checkoutURL), "https://") {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "paddle_checkout_url_missing"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "provider": "paddle", "plan": plan,
		"transaction_id": transactionID, "checkout_url": checkoutURL,
	})
}

func (h *Handler) PaddleWebhook(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_unavailable"})
		return
	}
	cfg := services.LoadPaddleConfigFromEnv()
	secret := strings.TrimSpace(cfg.WebhookSecret)
	if secret == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "paddle_webhook_not_configured"})
		return
	}
	raw, err := readBoundedWebhookBody(r.Body, paddleWebhookBodyLimit)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "webhook_body_too_large"})
		return
	}
	if err := verifyPaddleWebhookSignature(r.Header.Get("Paddle-Signature"), raw, secret, time.Now().UTC()); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_paddle_signature"})
		return
	}
	var envelope paddleWebhookEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_webhook_payload"})
		return
	}
	notificationID := strings.TrimSpace(envelope.NotificationID)
	if notificationID == "" {
		notificationID = strings.TrimSpace(envelope.EventID)
	}
	if notificationID == "" || strings.TrimSpace(envelope.EventType) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_webhook_identity"})
		return
	}

	// Unknown event types are acknowledged after signature verification. They are
	// not billing authority and therefore do not mutate entitlements.
	if envelope.EventType != "transaction.completed" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ignored": true, "event_type": envelope.EventType})
		return
	}
	var transaction paddleTransactionEvent
	if err := json.Unmarshal(envelope.Data, &transaction); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_transaction_event"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(transaction.Status), "completed") {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "transaction_not_completed"})
		return
	}
	transactionID := strings.TrimSpace(transaction.ID)
	plan := normalizePackageID(paddleCustomString(transaction.CustomData, "koschei_plan"))
	authSubject := strings.TrimSpace(paddleCustomString(transaction.CustomData, "koschei_auth_subject"))
	email := strings.ToLower(strings.TrimSpace(paddleCustomString(transaction.CustomData, "koschei_email")))
	if transactionID == "" || planTierRank(plan) == 0 || authSubject == "" || email == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "transaction_binding_missing"})
		return
	}
	expectedPrice := strings.TrimSpace(cfg.PriceID(plan))
	if expectedPrice == "" || !paddleTransactionHasPrice(transaction, expectedPrice) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "transaction_price_plan_mismatch"})
		return
	}
	var profileExists int
	if err := h.DB.QueryRowContext(r.Context(), `
		SELECT 1
		FROM app_user_profiles
		WHERE auth_subject=$1 AND lower(email)=lower($2) AND status='active'
		LIMIT 1`, authSubject, email).Scan(&profileExists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "transaction_customer_binding_mismatch"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "customer_binding_unavailable"})
		return
	}

	occurredAt := nullablePaddleTime(envelope.OccurredAt)
	var expiresAt any
	if transaction.BillingPeriod != nil {
		if parsed := nullablePaddleTime(transaction.BillingPeriod.EndsAt); parsed != nil {
			expiresAt = *parsed
		}
	}
	digest := sha256.Sum256(raw)
	rawHash := "sha256:" + hex.EncodeToString(digest[:])

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_transaction_unavailable"})
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), `
		INSERT INTO paddle_billing_events
		(notification_id,event_type,transaction_id,plan_id,auth_subject,email,raw_sha256,occurred_at,processed_at)
		VALUES ($1,$2,$3,$4,$5,lower($6),$7,$8,now())
		ON CONFLICT (notification_id) DO NOTHING`,
		notificationID, envelope.EventType, transactionID, plan, authSubject, email, rawHash, occurredAt)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_event_ledger_unavailable"})
		return
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_event_ledger_unavailable"})
		return
	}
	if inserted == 0 {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_duplicate_resolution_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "duplicate": true, "notification_id": notificationID})
		return
	}
	activation, err := activatePackageEntitlementDetailedTx(
		r.Context(), tx, email, plan, "paddle", transactionID, "", "", cfg.ProductID(plan), expiresAt,
	)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "entitlement_activation_failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_commit_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "provider": "paddle", "plan": plan,
		"notification_id": notificationID, "transaction_id": transactionID,
		"entitlement_activated": activation.Activated,
	})
}

func readBoundedWebhookBody(body io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(body, limit+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("webhook body exceeds limit")
	}
	return raw, nil
}

func verifyPaddleWebhookSignature(header string, raw []byte, secret string, now time.Time) error {
	var timestamp int64
	hashes := []string{}
	for _, part := range strings.Split(header, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "ts":
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return fmt.Errorf("invalid paddle timestamp")
			}
			timestamp = parsed
		case "h1":
			hashes = append(hashes, strings.ToLower(strings.TrimSpace(value)))
		}
	}
	if timestamp <= 0 || len(hashes) == 0 || strings.TrimSpace(secret) == "" {
		return fmt.Errorf("paddle signature fields missing")
	}
	signedAt := time.Unix(timestamp, 0).UTC()
	delta := now.Sub(signedAt)
	if delta < 0 {
		delta = -delta
	}
	if delta > paddleWebhookTimestampWindow {
		return fmt.Errorf("paddle signature timestamp outside tolerance")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write(raw)
	expected := mac.Sum(nil)
	for _, candidate := range hashes {
		decoded, err := hex.DecodeString(candidate)
		if err == nil && hmac.Equal(expected, decoded) {
			return nil
		}
	}
	return fmt.Errorf("paddle signature mismatch")
}

func paddleCustomString(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func paddleTransactionHasPrice(transaction paddleTransactionEvent, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}
	for _, item := range transaction.Items {
		if strings.TrimSpace(item.Price.ID) == expected || strings.TrimSpace(item.PriceID) == expected {
			return true
		}
	}
	return false
}

func nullablePaddleTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	parsed = parsed.UTC()
	return &parsed
}
