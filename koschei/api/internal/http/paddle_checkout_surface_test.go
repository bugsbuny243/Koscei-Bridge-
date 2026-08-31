package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRetiredPaddleBillingRoutesAreNotRegistered(t *testing.T) {
	mux := http.NewServeMux()
	registerBillingRoutes(mux, nil)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/paddle/public-config"},
		{method: http.MethodPost, path: "/api/paddle/checkout"},
		{method: http.MethodPost, path: "/api/v1/paddle/checkout"},
		{method: http.MethodPost, path: "/api/paddle/webhook"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
			if rr.Code != http.StatusNotFound {
				t.Fatalf("retired Paddle route %s %s returned %d, want 404", tc.method, tc.path, rr.Code)
			}
		})
	}
}

func TestRetiredPaddleCheckoutGetsDefaultSecurityPolicy(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNoContent)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://tradepigloball.co/paddle-checkout", nil))

	policy := rr.Header().Get("Content-Security-Policy")
	if policy != koscheiBaseCSP() {
		t.Fatalf("retired Paddle path received a non-default CSP: %s", policy)
	}
	if strings.Contains(strings.ToLower(policy), "paddle.com") {
		t.Fatalf("retired Paddle domain remains in CSP: %s", policy)
	}
	if !strings.Contains(rr.Header().Get("Permissions-Policy"), "payment=()") {
		t.Fatalf("retired Paddle path unexpectedly enables browser payment: %s", rr.Header().Get("Permissions-Policy"))
	}
}
