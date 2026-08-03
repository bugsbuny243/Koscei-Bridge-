package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMemberEmailProxyRequiresConfiguration(t *testing.T) {
	t.Setenv("NEON_AUTH_BASE_URL", "")
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"user@example.com","password":"secret-password"}`))
	recorder := httptest.NewRecorder()

	(&Handler{}).Login(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "neon_auth_not_configured") {
		t.Fatalf("response does not explain missing auth configuration: %s", recorder.Body.String())
	}
}

func TestMemberEmailProxyCallsNeonServerSideWithTrustedOrigin(t *testing.T) {
	var receivedPath string
	var receivedOrigin string
	var receivedPayload map[string]string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedOrigin = r.Header.Get("Origin")
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_credentials","message":"Invalid email or password"}`))
	}))
	defer provider.Close()

	t.Setenv("NEON_AUTH_BASE_URL", provider.URL)
	t.Setenv("PUBLIC_APP_URL", "https://tradepigloball.co")
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"USER@EXAMPLE.COM","password":"secret-password","callbackURL":"/dashboard"}`))
	recorder := httptest.NewRecorder()

	(&Handler{}).Login(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
	if receivedPath != "/sign-in/email" {
		t.Fatalf("provider path = %q, want /sign-in/email", receivedPath)
	}
	if receivedOrigin != "https://tradepigloball.co" {
		t.Fatalf("Origin = %q, want trusted production origin", receivedOrigin)
	}
	if receivedPayload["email"] != "user@example.com" {
		t.Fatalf("email = %q, want normalized email", receivedPayload["email"])
	}
	if receivedPayload["callbackURL"] != "https://tradepigloball.co/dashboard" {
		t.Fatalf("callbackURL = %q, want absolute production callback", receivedPayload["callbackURL"])
	}
	if !strings.Contains(recorder.Body.String(), "invalid_credentials") {
		t.Fatalf("provider JSON error was not preserved: %s", recorder.Body.String())
	}
}

func TestMemberAbsoluteAuthCallbackRejectsForeignHost(t *testing.T) {
	t.Setenv("PUBLIC_APP_URL", "https://tradepigloball.co")
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)

	got := memberAbsoluteAuthCallbackURL(req, "https://attacker.example/callback")
	if got != "https://tradepigloball.co/dashboard" {
		t.Fatalf("callback = %q, want production fallback", got)
	}
}
