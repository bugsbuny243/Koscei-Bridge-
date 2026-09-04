package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestOwnerUnifiedWalletRadarStatelessWithoutLiveEvidence(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest("POST", "/api/owner/radar/unified", nil)
	res := httptest.NewRecorder()
	classification := radarTargetClassification{
		Type: "wallet", Status: "verified", Evidence: "test wallet classification",
	}

	h.ownerUnifiedWalletRadarStateless(res, req, "Wallet111", "Wallet111", "solana-mainnet", classification, false)

	if res.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["ok"] != true {
		t.Fatalf("expected ok=true, got %#v", body["ok"])
	}
	if body["execution_mode"] != "stateless_live" {
		t.Fatalf("expected stateless_live execution mode, got %#v", body["execution_mode"])
	}
	if body["database_available"] != false {
		t.Fatalf("expected database_available=false, got %#v", body["database_available"])
	}
	if body["final_verdict_persistence"] != "database_unavailable" {
		t.Fatalf("unexpected persistence marker: %#v", body["final_verdict_persistence"])
	}
	actor, ok := body["actor_investigation"].(map[string]any)
	if !ok {
		t.Fatalf("actor_investigation missing: %#v", body["actor_investigation"])
	}
	if actor["rule_verdict_persistence"] != "database_unavailable" {
		t.Fatalf("unexpected actor persistence marker: %#v", actor["rule_verdict_persistence"])
	}
}
