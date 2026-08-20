package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPaddlePublicConfigExposesOnlyBrowserSafeValues(t *testing.T) {
	for key, value := range map[string]string{
		"PADDLE_ENV":                   "production",
		"PADDLE_API_KEY":               "pdl_live_apikey_private_test",
		"PADDLE_CLIENT_TOKEN":          "live_client_public_test",
		"PADDLE_WEBHOOK_SECRET":        "pdl_ntfset_private_test",
		"PADDLE_STARTER_PRICE_ID":      "pri_starter",
		"PADDLE_PROFESSIONAL_PRICE_ID": "pri_professional",
		"PADDLE_ENTERPRISE_PRICE_ID":   "pri_enterprise",
		"PUBLIC_APP_URL":               "https://tradepigloball.co",
	} {
		t.Setenv(key, value)
	}

	recorder := httptest.NewRecorder()
	(&Handler{}).PaddlePublicConfig(recorder, httptest.NewRequest(http.MethodGet, "/api/paddle/public-config", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode public Paddle config: %v", err)
	}
	if payload["client_token"] != "live_client_public_test" {
		t.Fatalf("client token missing from browser config: %#v", payload["client_token"])
	}
	body := recorder.Body.String()
	for _, secret := range []string{"pdl_live_apikey_private_test", "pdl_ntfset_private_test"} {
		if strings.Contains(body, secret) {
			t.Fatalf("server secret leaked in public config: %s", secret)
		}
	}
}
