package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNeonAuthStateSecretReusesExistingProductionSecrets(t *testing.T) {
	t.Setenv("NEON_AUTH_STATE_SECRET", "")
	t.Setenv("KOSCHEI_AUTH_STATE_SECRET", "")
	t.Setenv("USER_SESSION_SECRET", "")
	t.Setenv("OWNER_SECRET", "owner-secret")
	t.Setenv("KOSCHEI_OWNER_SECRET", "")
	t.Setenv("DATABASE_URL", "postgres://example")

	h := &Handler{AdminPassword: "admin-secret"}
	if got, want := h.neonAuthStateSecret(), "owner-secret"; got != want {
		t.Fatalf("neonAuthStateSecret() = %q, want %q", got, want)
	}
}

func TestNeonAuthStateSecretStillPrefersDedicatedOverride(t *testing.T) {
	t.Setenv("NEON_AUTH_STATE_SECRET", "state-secret")
	t.Setenv("KOSCHEI_AUTH_STATE_SECRET", "")
	t.Setenv("USER_SESSION_SECRET", "user-secret")
	t.Setenv("OWNER_SECRET", "owner-secret")
	t.Setenv("KOSCHEI_OWNER_SECRET", "")
	t.Setenv("DATABASE_URL", "postgres://example")

	h := &Handler{AdminPassword: "admin-secret"}
	if got, want := h.neonAuthStateSecret(), "state-secret"; got != want {
		t.Fatalf("neonAuthStateSecret() = %q, want %q", got, want)
	}
}

func TestSanitizeFrontendRedirectUsesClosedRouteSet(t *testing.T) {
	tests := map[string]string{
		"/dashboard":                 "/dashboard.html",
		"/hub.html":                  "/hub.html",
		"https://evil.example/steal": "",
		"//evil.example/steal":       "",
		"/dashboard?next=evil":       "",
		"/unknown":                   "",
	}
	for input, want := range tests {
		if got := sanitizeFrontendRedirect(input); got != want {
			t.Errorf("sanitizeFrontendRedirect(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestNeonAuthStateCannotCarryExternalRedirect(t *testing.T) {
	t.Setenv("NEON_AUTH_STATE_SECRET", "state-secret")
	h := &Handler{}
	state, err := h.newNeonAuthState("https://evil.example/steal")
	if err != nil {
		t.Fatal(err)
	}
	if redirect, ok := h.parseNeonAuthState(state); ok || redirect != "" {
		t.Fatalf("external redirect accepted: redirect=%q ok=%v", redirect, ok)
	}
}

func TestNeonCallbackBridgeEscapesQueryToken(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/auth/neon-callback?access_token=%3C/script%3E%3Cscript%3Ealert(1)%3C/script%3E", nil)
	recorder := httptest.NewRecorder()
	(&Handler{}).NeonCallback(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Location") != "" {
		t.Fatalf("callback status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	body := recorder.Body.String()
	if strings.Contains(body, "</script><script>") || !strings.Contains(body, `\u003c/script\u003e`) {
		t.Fatalf("callback token was not safely JSON-escaped: %s", body)
	}
}
