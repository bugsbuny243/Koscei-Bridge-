package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicHTMLAllowsOnlyPiControlledFrameAncestors(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>pi app</body></html>"))
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://tradepigloball.co/", nil))

	if got := recorder.Header().Get("X-Frame-Options"); got != "" {
		t.Fatalf("public Pi surface retained X-Frame-Options=%q", got)
	}
	policy := recorder.Header().Get("Content-Security-Policy")
	if strings.Contains(policy, "frame-ancestors 'none'") {
		t.Fatalf("public Pi surface still denies all framing: %s", policy)
	}
	for _, ancestor := range []string{"'self'", "https://app-cdn.minepi.com", "https://sandbox.minepi.com", "https://*.minepi.com", "https://*.pinet.com"} {
		if !strings.Contains(policy, ancestor) {
			t.Fatalf("Pi frame ancestor %q missing from policy: %s", ancestor, policy)
		}
	}
	if strings.Contains(policy, "frame-ancestors *") || strings.Contains(policy, "frame-ancestors https:") {
		t.Fatalf("Pi frame policy is broader than intended: %s", policy)
	}
}

func TestPaddleCheckoutRemainsNonEmbeddable(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>checkout</body></html>"))
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://tradepigloball.co/paddle-checkout", nil))

	if got := recorder.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("Paddle checkout X-Frame-Options=%q, want DENY", got)
	}
	if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("Paddle checkout lost frame-ancestors none: %s", recorder.Header().Get("Content-Security-Policy"))
	}
}
