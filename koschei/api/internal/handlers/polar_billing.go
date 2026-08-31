package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
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
	polarWebhookBodyLimit       = int64(1 << 20)
	polarWebhookTimestampWindow = 5 * time.Minute
	polarAPITimeout             = 12 * time.Second
)

type polarCheckoutRequest struct {
	Plan string `json:"plan"`
}

type polarCheckoutResponse struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type polarWebhookEnvelope struct {
	Type      string            `json:"type"`
	Timestamp string            `json:"timestamp"`
	Data      polarSubscription `json:"data"`
}

type polarSubscription struct {
	ID               string             `json:"id"`
	Status           string             `json:"status"`
	CustomerID       string             `json:"customer_id"`
	ProductID        string             `json:"product_id"`
	CheckoutID       string             `json:"checkout_id"`
	CurrentPeriodEnd string             `json:"current_period_end"`
	Metadata         map[string]any     `json:"metadata"`
	BillingReason    string             `json:"billing_reason"`
	Paid             bool               `json:"paid"`
	SubscriptionID   string             `json:"subscription_id"`
	Subscription     *polarSubscription `json:"subscription"`
}

type polarCheckoutCreate struct {
	Products      []string          `json:"products"`
	CustomerEmail string            `json:"customer_email"`
	SuccessURL    string            `json:"success_url,omitempty"`
	ReturnURL     string            `json:"return_url,omitempty"`
	Metadata      map[string]string `json:"metadata"`
}

func (h *Handler) PolarCheckout(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_unavailable"})
		return
	}
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var input polarCheckoutRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	plan := normalizePackageID(input.Plan)
	if plan == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_plan"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(normalizedClaimEmail(claims)))
	authSubject := strings.TrimSpace(claims.Sub)
	if email == "" || authSubject == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "verified_identity_required"})
		return
	}

	var profileExists int
	if err := h.DB.QueryRowContext(r.Context(), `
		SELECT 1 FROM app_user_profiles
		WHERE auth_subject=$1 AND lower(email)=lower($2) AND status='active'
		LIMIT 1`, authSubject, email).Scan(&profileExists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "customer_binding_mismatch"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "customer_binding_unavailable"})
		return
	}

	cfg := services.LoadPolarConfigFromEnv()
	productID := cfg.ProductID(plan)
	if !cfg.CheckoutConfigured(plan) || productID == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "polar_checkout_not_configured", "plan": plan})
		return
	}

	created, err := createPolarCheckout(r.Context(), http.DefaultClient, cfg, polarCheckoutCreate{
		Products:      []string{productID},
		CustomerEmail: email,
		SuccessURL:    cfg.SuccessURL,
		ReturnURL:     cfg.ReturnURL,
		Metadata: map[string]string{
			"koschei_auth_subject": authSubject,
			"koschei_email":        email,
			"koschei_plan":         plan,
		},
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "polar_checkout_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "provider": "polar", "plan": plan,
		"checkout_id": created.ID, "checkout_url": created.URL,
	})
}

func createPolarCheckout(ctx context.Context, client *http.Client, cfg services.PolarConfig, payload polarCheckoutCreate) (polarCheckoutResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return polarCheckoutResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, polarAPITimeout)
	defer cancel()
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/") + "/checkouts/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return polarCheckoutResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.AccessToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return polarCheckoutResponse{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, polarWebhookBodyLimit))
	if err != nil {
		return polarCheckoutResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return polarCheckoutResponse{}, fmt.Errorf("polar checkout status %d", resp.StatusCode)
	}
	var created polarCheckoutResponse
	if err := json.Unmarshal(raw, &created); err != nil {
		return polarCheckoutResponse{}, err
	}
	created.ID = strings.TrimSpace(created.ID)
	created.URL = strings.TrimSpace(created.URL)
	if created.ID == "" || !strings.HasPrefix(strings.ToLower(created.URL), "https://") {
		return polarCheckoutResponse{}, errors.New("polar checkout response missing secure URL")
	}
	return created, nil
}

func (h *Handler) PolarWebhook(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_unavailable"})
		return
	}
	cfg := services.LoadPolarConfigFromEnv()
	if !cfg.WebhookConfigured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "polar_webhook_not_configured"})
		return
	}
	raw, err := readPolarWebhookBody(r.Body, polarWebhookBodyLimit)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "webhook_body_too_large"})
		return
	}
	eventID, signedAt, err := verifyPolarWebhookSignature(
		r.Header.Get("webhook-id"),
		r.Header.Get("webhook-timestamp"),
		r.Header.Get("webhook-signature"),
		raw,
		cfg.WebhookSecret,
		time.Now().UTC(),
	)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_polar_signature"})
		return
	}
	var envelope polarWebhookEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_webhook_payload"})
		return
	}
	envelope.Type = strings.TrimSpace(envelope.Type)
	if eventID == "" || envelope.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_webhook_identity"})
		return
	}

	occurredAt := polarOccurredAt(envelope.Timestamp, signedAt)
	subscription := polarSubscriptionForEnvelope(envelope)
	subscription.ID = strings.TrimSpace(subscription.ID)
	subscription.ProductID = strings.TrimSpace(subscription.ProductID)
	plan := cfg.PlanForProduct(subscription.ProductID)
	authSubject := polarMetadataString(subscription.Metadata, "koschei_auth_subject")
	email := strings.ToLower(polarMetadataString(subscription.Metadata, "koschei_email"))
	metadataPlan := normalizePackageID(polarMetadataString(subscription.Metadata, "koschei_plan"))
	if metadataPlan != "" && plan != "" && metadataPlan != plan {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "subscription_product_plan_mismatch"})
		return
	}

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_transaction_unavailable"})
		return
	}
	defer tx.Rollback()

	digest := sha256.Sum256(raw)
	result, err := tx.ExecContext(r.Context(), `
		INSERT INTO billing_provider_events
		(provider,event_id,event_type,external_subscription_id,plan_id,auth_subject,email,product_id,raw_sha256,occurred_at,processed_at)
		VALUES ('polar',$1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF(lower($6),''),NULLIF($7,''),$8,$9,now())
		ON CONFLICT (provider,event_id) DO NOTHING`,
		eventID, envelope.Type, subscription.ID, plan, authSubject, email, subscription.ProductID,
		"sha256:"+hex.EncodeToString(digest[:]), occurredAt)
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
		_ = tx.Rollback()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "duplicate": true, "event_id": eventID})
		return
	}

	requiresSubscriptionBinding := envelope.Type == "subscription.active" || envelope.Type == "subscription.revoked" || polarIsPaidSubscriptionCycle(envelope)
	if requiresSubscriptionBinding {
		if subscription.ID == "" || plan == "" || metadataPlan != plan || authSubject == "" || email == "" {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "subscription_binding_missing"})
			return
		}
		var profileExists int
		if err := tx.QueryRowContext(r.Context(), `
			SELECT 1 FROM app_user_profiles
			WHERE auth_subject=$1 AND lower(email)=lower($2) AND status='active'
			LIMIT 1`, authSubject, email).Scan(&profileExists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "subscription_customer_binding_mismatch"})
				return
			}
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "customer_binding_unavailable"})
			return
		}
	}

	response := map[string]any{"ok": true, "provider": "polar", "event_id": eventID, "event_type": envelope.Type}
	switch envelope.Type {
	case "subscription.active":
		if !strings.EqualFold(strings.TrimSpace(subscription.Status), "active") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "subscription_not_active"})
			return
		}
		var newerRevocation int
		err := tx.QueryRowContext(r.Context(), `
			SELECT 1 FROM billing_provider_events
			WHERE provider='polar' AND external_subscription_id=$1 AND event_type='subscription.revoked'
			  AND occurred_at IS NOT NULL AND occurred_at >= $2
			LIMIT 1`, subscription.ID, occurredAt).Scan(&newerRevocation)
		if err == nil {
			if err := tx.Commit(); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_commit_failed"})
				return
			}
			response["activation_suppressed"] = true
			response["reason"] = "newer_or_equal_revocation_recorded"
			writeJSON(w, http.StatusOK, response)
			return
		}
		if !errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_ordering_check_unavailable"})
			return
		}
		expiresAt := polarNullableTime(subscription.CurrentPeriodEnd)
		activation, err := activatePackageEntitlementDetailedTx(
			r.Context(), tx, email, plan, "polar", subscription.ID, "", "", subscription.ProductID, expiresAt,
		)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "entitlement_activation_failed"})
			return
		}
		response["entitlement_activated"] = activation.Activated
		response["plan"] = plan
	case "order.paid":
		if !polarIsPaidSubscriptionCycle(envelope) {
			response["entitlement_changed"] = false
			break
		}
		if !strings.EqualFold(strings.TrimSpace(subscription.Status), "active") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "renewal_subscription_not_active"})
			return
		}
		refreshed, err := refreshPackageEntitlementPeriodTx(r.Context(), tx, "polar", subscription.ID, plan, polarNullableTime(subscription.CurrentPeriodEnd))
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "renewal_entitlement_missing"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "entitlement_renewal_failed"})
			return
		}
		response["entitlement_refreshed"] = true
		response["plan"] = refreshed.PackageID
		response["outputs_remaining"] = refreshed.OutputsRemaining
	case "subscription.revoked":
		revocation, err := revokePackageEntitlementDetailedTx(r.Context(), tx, "polar", subscription.ID)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "entitlement_revocation_failed"})
			return
		}
		response["entitlement_revoked"] = revocation.Revoked
		response["profile_plan"] = revocation.ProfilePlan
	case "subscription.canceled", "subscription.past_due", "subscription.updated", "subscription.created", "subscription.uncanceled":
		response["entitlement_changed"] = false
	default:
		response["ignored"] = true
	}

	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing_commit_failed"})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func readPolarWebhookBody(body io.Reader, limit int64) ([]byte, error) {
	if body == nil {
		return nil, errors.New("body missing")
	}
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("webhook body exceeds limit")
	}
	return raw, nil
}

// Polar's current signer and official SDKs use the literal configured webhook
// secret bytes as the HMAC key. This intentionally matches Polar delivery
// behavior rather than applying Standard Webhooks whsec_ key derivation.
func verifyPolarWebhookSignature(id, timestampHeader, signatureHeader string, raw []byte, secret string, now time.Time) (string, time.Time, error) {
	id = strings.TrimSpace(id)
	timestampHeader = strings.TrimSpace(timestampHeader)
	signatureHeader = strings.TrimSpace(signatureHeader)
	secret = strings.TrimSpace(secret)
	if id == "" || timestampHeader == "" || signatureHeader == "" || secret == "" {
		return "", time.Time{}, errors.New("polar signature fields missing")
	}
	timestamp, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return "", time.Time{}, errors.New("invalid polar webhook timestamp")
	}
	signedAt := time.Unix(timestamp, 0).UTC()
	delta := now.UTC().Sub(signedAt)
	if delta < -polarWebhookTimestampWindow || delta > polarWebhookTimestampWindow {
		return "", time.Time{}, errors.New("polar webhook timestamp outside tolerance")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(id))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write([]byte(timestampHeader))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(raw)
	expected := mac.Sum(nil)

	for _, candidate := range strings.Fields(signatureHeader) {
		version, encoded, ok := strings.Cut(candidate, ",")
		if !ok || strings.TrimSpace(version) != "v1" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err == nil && hmac.Equal(expected, decoded) {
			return id, signedAt, nil
		}
	}
	return "", time.Time{}, errors.New("polar webhook signature mismatch")
}

func polarIsPaidSubscriptionCycle(envelope polarWebhookEnvelope) bool {
	return envelope.Type == "order.paid" && envelope.Data.Paid && strings.EqualFold(strings.TrimSpace(envelope.Data.BillingReason), "subscription_cycle")
}

func polarSubscriptionForEnvelope(envelope polarWebhookEnvelope) polarSubscription {
	if envelope.Type != "order.paid" {
		return envelope.Data
	}
	order := envelope.Data
	if order.Subscription == nil {
		return polarSubscription{ID: strings.TrimSpace(order.SubscriptionID), ProductID: strings.TrimSpace(order.ProductID), Metadata: order.Metadata}
	}
	subscription := *order.Subscription
	if strings.TrimSpace(subscription.ID) == "" {
		subscription.ID = strings.TrimSpace(order.SubscriptionID)
	}
	if strings.TrimSpace(subscription.ProductID) == "" {
		subscription.ProductID = strings.TrimSpace(order.ProductID)
	}
	if len(subscription.Metadata) == 0 {
		subscription.Metadata = order.Metadata
	}
	return subscription
}

func polarMetadataString(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func polarNullableTime(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	return parsed.UTC()
}

func polarOccurredAt(value string, fallback time.Time) time.Time {
	value = strings.TrimSpace(value)
	if value != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return parsed.UTC()
		}
	}
	return fallback.UTC()
}
