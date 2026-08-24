package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQuotaResponseWriterDoesNotConsumeFailedWork(t *testing.T) {
	rr := httptest.NewRecorder()
	tracker := &quotaResponseWriter{ResponseWriter: rr, status: http.StatusOK}
	writeJSON(tracker, http.StatusBadGateway, map[string]string{"error": "rpc_failed"})
	if tracker.shouldConsumeQuota() {
		t.Fatal("failed work consumed a reserved SaaS output")
	}
}

func TestQuotaResponseWriterRefundsEvidencePending(t *testing.T) {
	rr := httptest.NewRecorder()
	tracker := &quotaResponseWriter{ResponseWriter: rr, status: http.StatusOK}
	writeJSON(tracker, http.StatusOK, map[string]any{"ok": true, "status": "evidence_pending", "charged": false})
	if tracker.shouldConsumeQuota() {
		t.Fatal("charged=false consumed a reserved SaaS output")
	}
}

func TestQuotaResponseWriterKeepsExplicitCharge(t *testing.T) {
	rr := httptest.NewRecorder()
	tracker := &quotaResponseWriter{ResponseWriter: rr, status: http.StatusOK}
	writeJSON(tracker, http.StatusOK, map[string]any{"ok": true, "status": "ready", "charged": true})
	if !tracker.shouldConsumeQuota() {
		t.Fatal("charged=true refunded a completed SaaS output")
	}
}

func TestQuotaResponseWriterHonorsNoConsumeHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	tracker := &quotaResponseWriter{ResponseWriter: rr, status: http.StatusOK}
	tracker.Header().Set("X-Koschei-Quota-Consume", "false")
	writeJSON(tracker, http.StatusOK, map[string]any{"ok": true})
	if tracker.shouldConsumeQuota() {
		t.Fatal("explicit no-consume header was ignored")
	}
}

func TestQuotaResponseWriterConsumesSuccessfulUnknownEnvelope(t *testing.T) {
	rr := httptest.NewRecorder()
	tracker := &quotaResponseWriter{ResponseWriter: rr, status: http.StatusOK}
	writeJSON(tracker, http.StatusOK, map[string]any{"ok": true})
	if !tracker.shouldConsumeQuota() {
		t.Fatal("successful work without charged=false should consume its reservation")
	}
}
