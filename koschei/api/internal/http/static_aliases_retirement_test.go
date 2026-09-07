package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRetiredStandaloneSurfacesRedirectToCanonicalProduct(t *testing.T) {
	mux := http.NewServeMux()
	registerStaticAliases(mux, t.TempDir())

	cases := map[string]string{
		"/feedback":                "/dashboard#feedback",
		"/feedback.html":           "/dashboard#feedback",
		"/exposure-report":         "/dashboard#exposure",
		"/exposure-report.html":    "/dashboard#exposure",
		"/security-ecosystem":      "/dashboard#capabilities",
		"/security-ecosystem.html": "/dashboard#capabilities",
		"/token-vesting":           "/",
		"/token-vesting.html":      "/",
	}

	for route, wantLocation := range cases {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route, nil)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusPermanentRedirect {
				t.Fatalf("%s status=%d, want %d", route, recorder.Code, http.StatusPermanentRedirect)
			}
			if got := recorder.Header().Get("Location"); got != wantLocation {
				t.Fatalf("%s Location=%q, want %q", route, got, wantLocation)
			}
		})
	}
}
