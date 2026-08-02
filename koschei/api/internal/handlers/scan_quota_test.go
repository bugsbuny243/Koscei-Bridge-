package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeScanQuotaLedger struct {
	reserveStatus scanQuotaStatus
	reserveErr    error
	refunds       int
	reserves      int
}

func (f *fakeScanQuotaLedger) Reserve(context.Context, string, string, string, int, time.Time) (premiumOutputReservation, scanQuotaStatus, error) {
	f.reserves++
	return premiumOutputReservation{
		Email: "user@example.com", QuotaDayKey: "kosch_daily_scan:2026-07-15",
		QuotaEventReason: "kosch_daily_scan:2026-07-15:test",
	}, f.reserveStatus, f.reserveErr
}

func (f *fakeScanQuotaLedger) Refund(context.Context, premiumOutputReservation) error {
	f.refunds++
	return nil
}

func (f *fakeScanQuotaLedger) Status(context.Context, string, string, int, time.Time) (scanQuotaStatus, error) {
	return f.reserveStatus, nil
}

func requestWithTokenAccess(tier string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/radar/detail", nil)
	ctx := withTokenAccessRequestContext(req.Context(), tokenAccessRequestContext{
		Evaluation:  tokenAccessEvaluation{GateEnabled: true, Configured: true, WalletVerified: true, Tier: tier},
		AuthSubject: "user-sub", Email: "user@example.com",
	})
	return req.WithContext(ctx)
}

func TestRequireTokenTierRejectsBasicUserFromProRoute(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/radar/actor-intelligence", nil)
	req = req.WithContext(context.WithValue(req.Context(), authContextKey, neonJWTClaims{Sub: "user-sub", Email: "user@example.com"}))
	rr := httptest.NewRecorder()
	called := false
	evaluator := func(context.Context, string) (tokenAccessEvaluation, error) {
		return tokenAccessEvaluation{GateEnabled: true, Configured: true, WalletVerified: true, Tier: "basic"}, nil
	}
	h.requireTokenTierWithEvaluator("pro", evaluator, func(http.ResponseWriter, *http.Request) { called = true })(rr, req)
	if called {
		t.Fatal("pro handler was called for basic tier")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["error"] != "token_tier_required" || body["required_tier"] != "pro" {
		t.Fatalf("unexpected response: %#v", body)
	}
}

func TestScanQuotaExceededReturns429(t *testing.T) {
	reset := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	ledger := &fakeScanQuotaLedger{reserveStatus: scanQuotaStatus{Tier: "basic", Limit: 5, Used: 5, Remaining: 0, ResetsAt: reset}, reserveErr: errScanQuotaExceeded}
	rr := httptest.NewRecorder()
	called := false
	enforceScanQuota(ledger, func(http.ResponseWriter, *http.Request) { called = true })(rr, requestWithTokenAccess("basic"))
	if called {
		t.Fatal("handler ran after quota was exhausted")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["error"] != "quota_exceeded" || int(body["limit"].(float64)) != 5 {
		t.Fatalf("unexpected quota response: %#v", body)
	}
}

func TestFailedWorkRefundsQuotaReservation(t *testing.T) {
	ledger := &fakeScanQuotaLedger{reserveStatus: scanQuotaStatus{Tier: "basic", Limit: 5, Used: 1, Remaining: 4, ResetsAt: time.Now().UTC().Add(time.Hour)}}
	rr := httptest.NewRecorder()
	enforceScanQuota(ledger, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "rpc_failed"})
	})(rr, requestWithTokenAccess("basic"))
	if ledger.reserves != 1 || ledger.refunds != 1 {
		t.Fatalf("reserve=%d refund=%d", ledger.reserves, ledger.refunds)
	}
}

func TestSuccessfulWorkKeepsQuotaReservation(t *testing.T) {
	ledger := &fakeScanQuotaLedger{reserveStatus: scanQuotaStatus{Tier: "pro", Limit: 100, Used: 1, Remaining: 99, ResetsAt: time.Now().UTC().Add(time.Hour)}}
	rr := httptest.NewRecorder()
	enforceScanQuota(ledger, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})(rr, requestWithTokenAccess("pro"))
	if ledger.reserves != 1 || ledger.refunds != 0 {
		t.Fatalf("reserve=%d refund=%d", ledger.reserves, ledger.refunds)
	}
}

func TestEvidencePendingResponseRefundsQuotaReservation(t *testing.T) {
	ledger := &fakeScanQuotaLedger{reserveStatus: scanQuotaStatus{Tier: "basic", Limit: 5, Used: 1, Remaining: 4, ResetsAt: time.Now().UTC().Add(time.Hour)}}
	rr := httptest.NewRecorder()
	enforceScanQuota(ledger, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "evidence_pending", "charged": false})
	})(rr, requestWithTokenAccess("basic"))
	if ledger.reserves != 1 || ledger.refunds != 1 {
		t.Fatalf("reserve=%d refund=%d", ledger.reserves, ledger.refunds)
	}
}

func TestExplicitChargedResponseKeepsQuotaReservation(t *testing.T) {
	ledger := &fakeScanQuotaLedger{reserveStatus: scanQuotaStatus{Tier: "basic", Limit: 5, Used: 1, Remaining: 4, ResetsAt: time.Now().UTC().Add(time.Hour)}}
	rr := httptest.NewRecorder()
	enforceScanQuota(ledger, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "ready", "charged": true})
	})(rr, requestWithTokenAccess("basic"))
	if ledger.reserves != 1 || ledger.refunds != 0 {
		t.Fatalf("reserve=%d refund=%d", ledger.reserves, ledger.refunds)
	}
}

func TestUTCQuotaWindowResetsAtNextDay(t *testing.T) {
	start, reset, key := utcQuotaWindow(time.Date(2026, 7, 15, 23, 59, 59, 0, time.FixedZone("west", -7*3600)))
	if start.Location() != time.UTC || reset.Sub(start) != 24*time.Hour || key != "kosch_daily_scan:2026-07-16" {
		t.Fatalf("start=%s reset=%s key=%s", start, reset, key)
	}
}

func TestQuotaDefaultsAndOverrides(t *testing.T) {
	t.Setenv("KOSCHEI_QUOTA_BASIC_DAILY", "")
	t.Setenv("KOSCHEI_QUOTA_PRO_DAILY", "77")
	if got := configuredKOSCHDailyQuota("basic"); got != 5 {
		t.Fatalf("basic default=%d", got)
	}
	if got := configuredKOSCHDailyQuota("pro"); got != 77 {
		t.Fatalf("pro override=%d", got)
	}
	if !errors.Is(errScanQuotaExceeded, errScanQuotaExceeded) {
		t.Fatal("quota error sentinel is not stable")
	}
}
