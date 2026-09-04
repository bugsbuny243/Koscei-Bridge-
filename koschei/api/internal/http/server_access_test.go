package http

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"koschei/api/internal/handlers"
)

func TestProductRouteTierMapAndFreeCore(t *testing.T) {
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

	// SaaS plan names are the route authorization contract: Starter includes the
	// paid investigation routes and canonical durable-job create routes. Professional
	// preflight and advanced radar outputs are metered; the immediate state recheck
	// is entitlement-only so the same signing decision is not charged twice. Job
	// reads remain authenticated but are not counted here because they do not
	// consume a new premium output.
	wantMetered := []string{"starter", "starter", "starter", "starter", "starter", "starter", "professional", "professional", "professional", "professional", "professional", "professional", "professional"}
	if !reflect.DeepEqual(meteredTiers, wantMetered) {
		t.Fatalf("metered route tiers=%v want=%v", meteredTiers, wantMetered)
	}
	wantAccess := []string{"professional"}
	if !reflect.DeepEqual(accessTiers, wantAccess) {
		t.Fatalf("entitlement-only route tiers=%v want=%v", accessTiers, wantAccess)
	}

	// A GET reaches the free route's method guard directly. A SaaS entitlement
	// gate would have been registered through the SaaS gates above and changed the tier lists.
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/token/scan", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("free token scan unexpectedly gated: status=%d body=%s", rr.Code, rr.Body.String())
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
