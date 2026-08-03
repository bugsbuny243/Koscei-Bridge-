package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLegacyScanRoutesRedirectToCanonicalModes(t *testing.T) {
	tests := []struct {
		path     string
		location string
	}{
		{path: "/safe-check", location: "/scan?mode=quick"},
		{path: "/safe-check/", location: "/scan?mode=quick"},
		{path: "/safe-check.html", location: "/scan?mode=quick"},
		{path: "/transaction-shield", location: "/scan?mode=transaction"},
		{path: "/transaction-shield/", location: "/scan?mode=transaction"},
		{path: "/transaction-shield.html", location: "/scan?mode=transaction"},
		{path: "/security-radar", location: "/scan?mode=deep"},
		{path: "/security-radar/", location: "/scan?mode=deep"},
		{path: "/security-radar.html", location: "/scan?mode=deep"},
		{path: "/security-radar?target=Mint123", location: "/scan?mode=deep&target=Mint123"},
	}

	mux := http.NewServeMux()
	registerStaticAliases(mux, t.TempDir())

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusPermanentRedirect {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusPermanentRedirect)
			}
			if location := response.Header().Get("Location"); location != test.location {
				t.Fatalf("Location = %q, want %q", location, test.location)
			}
		})
	}
}

func TestLegacyScanRedirectsRejectWrites(t *testing.T) {
	mux := http.NewServeMux()
	registerStaticAliases(mux, t.TempDir())
	request := httptest.NewRequest(http.MethodPost, "/safe-check", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}
