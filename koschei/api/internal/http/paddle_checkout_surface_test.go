package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPaddleCheckoutCSPIsNarrowAndAllowsPaddle(t *testing.T) {
	policy := paddleCheckoutCSP()
	for _, required := range []string{
		"script-src 'self' https://cdn.paddle.com",
		"connect-src 'self' https://paddle.com https://*.paddle.com",
		"frame-src https://paddle.com https://*.paddle.com",
		"script-src-attr 'none'",
	} {
		if !strings.Contains(policy, required) {
			t.Fatalf("Paddle checkout CSP missing %q: %s", required, policy)
		}
	}
	if strings.Contains(policy, "'unsafe-inline'") || strings.Contains(policy, " https: ") {
		t.Fatalf("Paddle checkout CSP is too broad: %s", policy)
	}
}

func TestSecurityHeadersKeepsPaymentFeatureAvailableOnlyOnPaddleCheckout(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>checkout</body></html>"))
	}))

	checkout := httptest.NewRecorder()
	handler.ServeHTTP(checkout, httptest.NewRequest(http.MethodGet, "https://tradepigloball.co/paddle-checkout", nil))
	if strings.Contains(checkout.Header().Get("Permissions-Policy"), "payment=()") {
		t.Fatalf("checkout disabled browser payment feature: %s", checkout.Header().Get("Permissions-Policy"))
	}
	if !strings.Contains(checkout.Header().Get("Content-Security-Policy"), "https://cdn.paddle.com") {
		t.Fatalf("checkout CSP does not allow Paddle.js: %s", checkout.Header().Get("Content-Security-Policy"))
	}

	normal := httptest.NewRecorder()
	handler.ServeHTTP(normal, httptest.NewRequest(http.MethodGet, "https://tradepigloball.co/", nil))
	if !strings.Contains(normal.Header().Get("Permissions-Policy"), "payment=()") {
		t.Fatalf("non-checkout surface unexpectedly enables browser payment feature: %s", normal.Header().Get("Permissions-Policy"))
	}
}
