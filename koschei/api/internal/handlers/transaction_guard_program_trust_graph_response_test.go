package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTransactionGuardResponseExposesProgramTrustGraphWithoutChangingVerdict(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "false")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "false")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", "")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "")

	input := transactionGuardV2Request{Transaction: "program-trust-fixture", Network: "solana-mainnet", Encoding: "base64"}
	assessment := transactionFirewallAssessment{Action: "allow", RiskLevel: "low", RiskIndex: 0, SimulationOK: true}
	decoded := transactionGuardDecodedTransaction{Complete: true, Available: true, ProgramIDs: []string{guardV3SPLTokenProgramID}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/shield/transaction", nil)
	stateWitness := unavailableTransactionGuardStateWitness(transactionFingerprint(input.Transaction), 0, "fixture")

	(&Handler{}).finishTransactionGuardV3ResponseWithWitness(
		recorder,
		request,
		input,
		"req-program-trust",
		time.Now(),
		assessment,
		transactionGuardProgramPolicy{Complete: true},
		transactionGuardIntentPolicy{Complete: true, Accounts: []transactionGuardAccountDelta{}},
		decoded,
		transactionGuardThreatHistoryAnalysis{},
		transactionGuardCPIFlowAnalysis{},
		transactionGuardAuthoritySurfaceAnalysis{},
		stateWitness,
		"",
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["action"] != "allow" || body["risk_level"] != "low" {
		t.Fatalf("Program Trust Graph changed verdict: %#v", body)
	}
	if body["program_trust_graph_complete"] != false {
		t.Fatalf("expected incomplete graph without DB snapshot source: %#v", body["program_trust_graph_complete"])
	}
	graph, ok := body["program_trust_graph"].(map[string]any)
	if !ok {
		t.Fatalf("program trust graph missing: %#v", body["program_trust_graph"])
	}
	if graph["version"] != transactionGuardProgramTrustGraphVersion || graph["status"] != "partial" || graph["verdict_authority"] != false {
		t.Fatalf("graph=%#v", graph)
	}
}
