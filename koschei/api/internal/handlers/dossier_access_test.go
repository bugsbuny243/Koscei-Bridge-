package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDossierOwnerCredentialDetection(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dossier/Mint111", nil)
	if dossierOwnerCredentialPresent(req) {
		t.Fatal("empty request detected as owner")
	}
	req.Header.Set("x-koschei-secret", "secret")
	if !dossierOwnerCredentialPresent(req) {
		t.Fatal("owner header was not detected")
	}
}

func TestDossierOwnerCookieDetection(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dossier/Mint111", nil)
	req.AddCookie(&http.Cookie{Name: "koschei_owner_secret", Value: "secret"})
	if !dossierOwnerCredentialPresent(req) {
		t.Fatal("owner cookie was not detected")
	}
}
