package handlers

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func transactionGuardStateRecheckHandlerFixture(t *testing.T) (transactionGuardStateRecheckRequest, *services.SolanaAccountInfo, *services.SolanaAccountInfo) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(40 + index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	accountA := &services.SolanaAccountInfo{Lamports: 11, Owner: "OwnerA", Data: []any{"QQ==", "base64"}, Space: 165}
	accountB := &services.SolanaAccountInfo{Lamports: 22, Owner: "OwnerB", Data: []any{"Qg==", "base64"}, Space: 165}
	transaction := base64.StdEncoding.EncodeToString([]byte("state-recheck-live-transaction"))
	witness := buildTransactionGuardStateWitness(
		transactionFingerprint(transaction),
		700,
		702,
		[]string{"AddrA", "AddrB"},
		[]*services.SolanaAccountInfo{accountA, accountB},
	)
	if !witness.Complete {
		t.Fatalf("fixture witness incomplete: %#v", witness)
	}
	now := time.Now().UTC().Add(-10 * time.Second)
	permit, err := signTransactionGuardEnforcementPermitWithWitness(
		privateKey,
		"recheck-live-key",
		2*time.Minute,
		transactionGuardV2Request{Transaction: transaction, Network: "solana-mainnet", Encoding: "base64"},
		"req-live-recheck",
		transactionFirewallAssessment{Action: "allow"},
		now,
		&witness,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "recheck-live-key")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(privateKey))
	return transactionGuardStateRecheckRequest{
		PermitToken: permit.Token, Transaction: transaction, Network: "solana-mainnet", StateWitness: witness,
	}, accountA, accountB
}

func stateRecheckRPCServer(t *testing.T, slot int64, accounts []*services.SolanaAccountInfo, called *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if called != nil {
			called.Store(true)
		}
		var request struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode rpc request: %v", err)
		}
		if request.Method != "getMultipleAccounts" {
			t.Errorf("rpc method=%q want getMultipleAccounts", request.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"context": map[string]any{"slot": slot},
				"value":   accounts,
			},
		})
	}))
}

func executeStateRecheckRequest(t *testing.T, input transactionGuardStateRecheckRequest) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/shield/state-recheck", bytes.NewReader(payload))
	response := httptest.NewRecorder()
	(&Handler{}).TransactionGuardStateRecheck(response, request)
	return response
}

func TestTransactionGuardStateRecheckEndpointConfirmsUnchangedState(t *testing.T) {
	input, accountA, accountB := transactionGuardStateRecheckHandlerFixture(t)
	var called atomic.Bool
	server := stateRecheckRPCServer(t, 710, []*services.SolanaAccountInfo{accountA, accountB}, &called)
	defer server.Close()
	t.Setenv("SOLANA_RPC_URL", server.URL)

	response := executeStateRecheckRequest(t, input)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !called.Load() {
		t.Fatal("trusted recheck did not query bounded account state")
	}
	var body struct {
		OK       bool                                 `json:"ok"`
		Decision transactionGuardStateRecheckDecision `json:"decision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || body.Decision.Status != "state_unchanged" || !body.Decision.StateUnchanged || body.Decision.RequiresResimulation {
		t.Fatalf("body=%#v raw=%s", body, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "OwnerA") || strings.Contains(response.Body.String(), "QQ==") {
		t.Fatalf("raw account state leaked in response: %s", response.Body.String())
	}
}

func TestTransactionGuardStateRecheckEndpointRequiresFreshSimulationOnStateChange(t *testing.T) {
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
		Decision transactionGuardStateRecheckDecision `json:"decision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Decision.Status != "state_changed" || body.Decision.StateUnchanged || !body.Decision.RequiresResimulation || body.Decision.Action != "recheck_required" {
		t.Fatalf("decision=%#v", body.Decision)
	}
}

func TestTransactionGuardStateRecheckEndpointWithholdsStaleProviderState(t *testing.T) {
	input, accountA, accountB := transactionGuardStateRecheckHandlerFixture(t)
	server := stateRecheckRPCServer(t, 701, []*services.SolanaAccountInfo{accountA, accountB}, nil)
	defer server.Close()
	t.Setenv("SOLANA_RPC_URL", server.URL)

	response := executeStateRecheckRequest(t, input)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Decision transactionGuardStateRecheckDecision `json:"decision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Decision.Status != "withhold" || body.Decision.StateUnchanged || !body.Decision.RequiresResimulation {
		t.Fatalf("decision=%#v", body.Decision)
	}
}

func TestTransactionGuardStateRecheckRejectsInvalidPermitBeforeRPC(t *testing.T) {
	input, accountA, accountB := transactionGuardStateRecheckHandlerFixture(t)
	input.PermitToken += "tampered"
	var called atomic.Bool
	server := stateRecheckRPCServer(t, 710, []*services.SolanaAccountInfo{accountA, accountB}, &called)
	defer server.Close()
	t.Setenv("SOLANA_RPC_URL", server.URL)

	response := executeStateRecheckRequest(t, input)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if called.Load() {
		t.Fatal("invalid permit reached RPC provider")
	}
}
