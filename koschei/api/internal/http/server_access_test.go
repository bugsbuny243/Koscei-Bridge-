package http

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"koschei/api/internal/handlers"
)

func TestProductRouteTierMapIsProfessionalOnly(t *testing.T) {
	mux := http.NewServeMux()
	h := &handlers.Handler{}
	meteredTiers := []string{}
	accessTiers := []string{}
	meteredGate := func(tier string, next http.HandlerFunc) http.HandlerFunc {
		meteredTiers = append(meteredTiers, tier)
		return next
	}
	accessGate := func(tier string, next http.HandlerFunc) http.HandlerFunc {
		accessTiers = append(accessTiers, tier)
		return next
	}
	registerProductRoutes(mux, h, meteredGate, accessGate)

	// Professional is the single operational customer SaaS entitlement. All
	// metered investigation, radar and durable-job create routes use the same
	// Professional authorization contract. The immediate state recheck remains
	// entitlement-only so one signing decision is not charged twice.
	wantMetered := []string{"professional", "professional", "professional", "professional", "professional", "professional", "professional", "professional", "professional", "professional", "professional", "professional", "professional"}
	if !reflect.DeepEqual(meteredTiers, wantMetered) {
		t.Fatalf("metered route tiers=%v want=%v", meteredTiers, wantMetered)
	}
	wantAccess := []string{"professional"}
	if !reflect.DeepEqual(accessTiers, wantAccess) {
		t.Fatalf("entitlement-only route tiers=%v want=%v", accessTiers, wantAccess)
	}

	// The legacy route registrations stay physically present for compatibility,
	// but the outer HTTP readiness boundary classifies them as Professional-only.
	for _, path := range []string{"/api/token/scan", "/api/arvis/preflight"} {
		if !requiresProfessionalLegacyOperation(path) {
			t.Fatalf("legacy operational route %s is not Professional-gated", path)
		}
		if allowedWithoutDatabase(path) {
			t.Fatalf("legacy operational route %s still has stateless/free execution semantics", path)
		}
	}
}

func TestRequiresDBAllowsExplicitStatelessRoute(t *testing.T) {
	h := &handlers.Handler{}
	called := false
	next := requiresDB(h, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	rr := httptest.NewRecorder()
	next(rr, httptest.NewRequest(http.MethodPost, "/api/owner/arvis/scan", nil))

	if !called {
		t.Fatal("explicit stateless route was blocked by the database gate")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("stateless route status=%d want=%d body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
}

func TestRequiresDBStillBlocksDurableJobRouteWithoutDatabase(t *testing.T) {
	h := &handlers.Handler{}
	called := false
	next := requiresDB(h, func(http.ResponseWriter, *http.Request) {
		called = true
	})

	rr := httptest.NewRecorder()
	next(rr, httptest.NewRequest(http.MethodPost, "/api/owner/radar/jobs", nil))

	if called {
		t.Fatal("durable job route ran without its database")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("durable job route status=%d want=%d body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
}
