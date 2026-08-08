package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveredFeatureGateBlocksDisabledRiskScanner(t *testing.T) {
	t.Setenv("FEATURE_RISK_SCANNER", "false")
	called := false
	h := requireRuntimeFeature(featureRiskScanner, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/token/scan", nil))
	if called || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("called=%v status=%d", called, rec.Code)
	}
}

func TestRecoveredFeatureGateAllowsEnabledSolana(t *testing.T) {
	t.Setenv("FEATURE_SOLANA", "true")
	called := false
	h := requireRuntimeFeature(featureSolana, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/public/transaction-simulate", nil))
	if !called || rec.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d", called, rec.Code)
	}
}
