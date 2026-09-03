package handlers

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestOwnerSessionWorksInProductionNeonAuthOnlyMode(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_NEON_AUTH_ONLY", "true")
	resetOwnerSessionMemoryForTest()

	h := &Handler{}
	login := httptest.NewRequest("POST", "https://example.test/api/owner/login", nil)
	login.RemoteAddr = "203.0.113.4:4000"
	token, expiresAt, err := h.issueOwnerSession(context.Background(), "owner-wallet", login)
	if err != nil || token == "" || expiresAt.IsZero() {
		t.Fatalf("issue session token=%q expires=%v err=%v", token, expiresAt, err)
	}

	request := httptest.NewRequest("GET", "https://example.test/api/owner/operations", nil)
	request.AddCookie(&http.Cookie{Name: ownerSessionCookieName, Value: token})
	wallet, ok := h.ownerSessionFromRequest(context.Background(), request)
	if !ok || wallet != normalizeWallet("owner-wallet") {
		t.Fatalf("session lookup wallet=%q ok=%v", wallet, ok)
	}
}

func TestOwnerSessionStillFailsClosedInProductionOutsideAuthOnlyMode(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_NEON_AUTH_ONLY", "false")
	resetOwnerSessionMemoryForTest()

	h := &Handler{}
	request := httptest.NewRequest("POST", "https://example.test/api/owner/login", nil)
	if _, _, err := h.issueOwnerSession(context.Background(), "owner-wallet", request); err == nil {
		t.Fatal("expected production session issue to fail without DB outside auth-only mode")
	}
}
