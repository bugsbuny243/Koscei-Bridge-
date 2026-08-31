package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestNormalizePaymentProviderAdmitsPolarAndRejectsRetiredPaddle(t *testing.T) {
	if got := normalizePaymentProvider(" POLAR "); got != "polar" {
		t.Fatalf("polar provider = %q", got)
	}
	for _, retired := range []string{"paddle", "unknown", ""} {
		if got := normalizePaymentProvider(retired); got != "" {
			t.Fatalf("provider %q unexpectedly normalized to %q", retired, got)
		}
	}
}

func TestVerifyPolarWebhookSignatureUsesLiteralSecretAndReplayWindow(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	id := "evt_123"
	ts := strconv.FormatInt(now.Unix(), 10)
	raw := []byte(`{"type":"subscription.active"}`)
	secret := "polar_whs_literal_secret"

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(id + "." + ts + "."))
	_, _ = mac.Write(raw)
	signature := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	gotID, signedAt, err := verifyPolarWebhookSignature(id, ts, "v1,AAAA "+signature, raw, secret, now)
	if err != nil {
		t.Fatalf("valid Polar signature rejected: %v", err)
	}
	if gotID != id || !signedAt.Equal(now) {
		t.Fatalf("unexpected verified identity/time: %q %s", gotID, signedAt)
	}

	if _, _, err := verifyPolarWebhookSignature(id, ts, signature, append(raw, ' '), secret, now); err == nil {
		t.Fatal("mutated body accepted")
	}
	stale := strconv.FormatInt(now.Add(-polarWebhookTimestampWindow-time.Second).Unix(), 10)
	if _, _, err := verifyPolarWebhookSignature(id, stale, signature, raw, secret, now); err == nil {
		t.Fatal("stale signed timestamp accepted")
	}
	future := strconv.FormatInt(now.Add(polarWebhookTimestampWindow+time.Second).Unix(), 10)
	if _, _, err := verifyPolarWebhookSignature(id, future, signature, raw, secret, now); err == nil {
		t.Fatal("future signed timestamp accepted")
	}
}

func TestCreatePolarCheckoutSendsServerBoundProductAndMetadata(t *testing.T) {
	var received polarCheckoutCreate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/checkouts/" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode checkout body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"checkout_123","url":"https://checkout.polar.sh/checkout_123"}`))
	}))
	defer server.Close()

	cfg := services.PolarConfig{AccessToken: "test-token", APIBaseURL: server.URL + "/v1"}
	payload := polarCheckoutCreate{
		Products:      []string{"prod_professional"},
		CustomerEmail: "user@example.com",
		SuccessURL:    "https://tradepigloball.co/account?billing=success",
		Metadata: map[string]string{
			"koschei_auth_subject": "auth-123",
			"koschei_email":        "user@example.com",
			"koschei_plan":         "professional",
		},
	}
	created, err := createPolarCheckout(context.Background(), server.Client(), cfg, payload)
	if err != nil {
		t.Fatalf("create checkout: %v", err)
	}
	if created.ID != "checkout_123" || !strings.HasPrefix(created.URL, "https://") {
		t.Fatalf("unexpected checkout response: %#v", created)
	}
	if len(received.Products) != 1 || received.Products[0] != "prod_professional" {
		t.Fatalf("server-bound products = %#v", received.Products)
	}
	if received.Metadata["koschei_plan"] != "professional" || received.CustomerEmail != "user@example.com" {
		t.Fatalf("binding metadata lost: %#v", received)
	}
}

func TestCreatePolarCheckoutRejectsInsecureHostedURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"checkout_123","url":"http://attacker.invalid/checkout"}`))
	}))
	defer server.Close()

	_, err := createPolarCheckout(context.Background(), server.Client(), services.PolarConfig{
		AccessToken: "test-token",
		APIBaseURL:  server.URL,
	}, polarCheckoutCreate{Products: []string{"prod_starter"}})
	if err == nil {
		t.Fatal("insecure checkout URL accepted")
	}
}
