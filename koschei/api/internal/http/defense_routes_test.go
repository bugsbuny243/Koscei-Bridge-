package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"koschei/api/internal/handlers"
)

func TestDefenseOSRoutesAreDormantByDefault(t *testing.T) {
	t.Setenv("KOSCHEI_DEFENSE_OS_ENABLED", "")
	mux := http.NewServeMux()
	registerDefenseOSRoutes(mux, &handlers.Handler{})

	req := httptest.NewRequest(http.MethodGet, "/api/owner/defense/artifacts", nil)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("expected dormant Defense OS route to be absent, got %d", res.Code)
	}
}

func TestDefenseOSRoutesCanBeExplicitlyEnabled(t *testing.T) {
	t.Setenv("KOSCHEI_DEFENSE_OS_ENABLED", "true")
	mux := http.NewServeMux()
	registerDefenseOSRoutes(mux, &handlers.Handler{})

	req := httptest.NewRequest(http.MethodGet, "/api/owner/defense/artifacts", nil)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code == http.StatusNotFound {
		t.Fatal("explicitly enabled Defense OS route was not registered")
	}
}
