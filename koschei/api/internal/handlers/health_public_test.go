package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCachedArvisHealthSnapshotDoesNotTriggerCollection(t *testing.T) {
	resetArvisHealthCache()
	snapshot := cachedArvisHealthSnapshot()
	if snapshot["pipeline_status"] != "live_provider_mode" || snapshot["cached"] != false {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	if snapshot["details_url"] != "/api/web3/health" {
		t.Fatalf("details_url=%v", snapshot["details_url"])
	}
}

func TestCachedArvisHealthSnapshotCopiesCachedData(t *testing.T) {
	resetArvisHealthCache()
	arvisHealthCache.Lock()
	arvisHealthCache.data = map[string]any{"pipeline_status": "operational", "visible_verdicts": int64(3)}
	arvisHealthCache.expiresAt = time.Now().Add(time.Minute)
	arvisHealthCache.Unlock()

	snapshot := cachedArvisHealthSnapshot()
	if snapshot["pipeline_status"] != "operational" || snapshot["cached"] != true {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	snapshot["pipeline_status"] = "mutated"
	arvisHealthCache.RLock()
	defer arvisHealthCache.RUnlock()
	if arvisHealthCache.data["pipeline_status"] != "operational" {
		t.Fatal("public snapshot mutated shared cache")
	}
}

func TestPublicHealthStaysReadyInStatelessRuntimeWithoutLeakingDBError(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	h := &Handler{DBInitError: "secret database connection detail"}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()

	started := time.Now()
	h.Health(recorder, req)
	if elapsed := time.Since(started); elapsed > publicHealthTimeout {
		t.Fatalf("health exceeded public timeout: %s", elapsed)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "secret database connection detail") {
		t.Fatalf("production health leaked database details: %s", recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, leaked := body["details"]; leaked {
		t.Fatalf("production health leaked database details: %#v", body)
	}
	if body["service"] != "koschei-web3" || body["status"] != "ok" || body["database"] != "not_used" || body["persistence"] != "stateless" {
		t.Fatalf("body=%#v", body)
	}
}
