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

	for _, header := range []string{"x-koschei-secret", "x-owner-secret", "x-admin-password"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/dossier/Mint111", nil)
		req.Header.Set(header, "secret")
		if !dossierOwnerCredentialPresent(req) {
			t.Fatalf("owner header %s was not detected", header)
		}
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/dossier/Mint111", nil)
	req.AddCookie(&http.Cookie{Name: "koschei_owner_secret", Value: "secret"})
	if !dossierOwnerCredentialPresent(req) {
		t.Fatal("owner cookie was not detected")
	}
}
