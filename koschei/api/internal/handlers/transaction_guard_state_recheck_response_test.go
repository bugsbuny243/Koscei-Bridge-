package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"koschei/api/internal/services"
)

func TestTransactionGuardStateRecheckSafeToProceedRequiresExactConsistentDecision(t *testing.T) {
	decision := transactionGuardStateRecheckDecision{
		Version:              transactionGuardStateRecheckVersion,
		Status:               "state_unchanged",
		Action:               "permit_state_consistent",
		StateUnchanged:       true,
		RequiresResimulation: false,
		IssuedStateRoot:      "root-a",
		CurrentStateRoot:     "root-a",
		SimulationSlot:       100,
		CurrentStateSlot:     101,
	}
	if !transactionGuardStateRecheckSafeToProceed(decision) {
		t.Fatalf("expected safe decision: %#v", decision)
	}
	mutations := []func(*transactionGuardStateRecheckDecision){
		func(value *transactionGuardStateRecheckDecision) { value.Status = "withhold" },
		func(value *transactionGuardStateRecheckDecision) { value.Action = "recheck_required" },
		func(value *transactionGuardStateRecheckDecision) { value.StateUnchanged = false },
		func(value *transactionGuardStateRecheckDecision) { value.RequiresResimulation = true },
		func(value *transactionGuardStateRecheckDecision) { value.CurrentStateRoot = "root-b" },
		func(value *transactionGuardStateRecheckDecision) { value.CurrentStateSlot = 99 },
	}
	for index, mutate := range mutations {
		candidate := decision
		mutate(&candidate)
		if transactionGuardStateRecheckSafeToProceed(candidate) {
			t.Fatalf("unsafe mutation %d passed: %#v", index, candidate)
		}
	}
}

func TestStateRecheckEndpointSafeToProceedTrueOnlyForUnchangedState(t *testing.T) {
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "false")
	input, accountA, accountB := transactionGuardStateRecheckHandlerFixture(t)
	server := stateRecheckRPCServer(t, 710, []*services.SolanaAccountInfo{accountA, accountB}, nil)
	defer server.Close()
	t.Setenv("SOLANA_RPC_URL", server.URL)

	response := executeStateRecheckRequest(t, input)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		OK            bool                                 `json:"ok"`
		SafeToProceed bool                                 `json:"safe_to_proceed"`
		Decision      transactionGuardStateRecheckDecision `json:"decision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || !body.SafeToProceed || body.Decision.Status != "state_unchanged" {
		t.Fatalf("body=%#v raw=%s", body, response.Body.String())
	}
}

func TestStateRecheckEndpointSafeToProceedFalseOnStateChange(t *testing.T) {
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "false")
	input, accountA, accountB := transactionGuardStateRecheckHandlerFixture(t)
	changedA := *accountA
	changedA.Lamports++
	server := stateRecheckRPCServer(t, 711, []*services.SolanaAccountInfo{&changedA, accountB}, nil)
	defer server.Close()
	t.Setenv("SOLANA_RPC_URL", server.URL)

	response := executeStateRecheckRequest(t, input)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		SafeToProceed bool                                 `json:"safe_to_proceed"`
		Decision      transactionGuardStateRecheckDecision `json:"decision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.SafeToProceed || body.Decision.Status != "state_changed" || !body.Decision.RequiresResimulation {
		t.Fatalf("body=%#v raw=%s", body, response.Body.String())
	}
}
