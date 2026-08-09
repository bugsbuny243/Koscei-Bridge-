package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func completeGuardResponseFixture(t *testing.T) (transactionGuardV2Request, transactionFirewallAssessment, transactionGuardStateWitness) {
	t.Helper()
	input := transactionGuardV2Request{
		Transaction: "fixture-transaction",
		Encoding:    "base64",
		Network:     "solana-mainnet",
	}
	assessment := transactionFirewallAssessment{
		Action:       "allow",
		RiskLevel:    "low",
		SimulationOK: true,
		Findings:     []transactionFirewallFinding{},
		Logs:         []string{},
	}
	witness := buildTransactionGuardStateWitness(
		transactionFingerprint(input.Transaction),
		900,
		901,
		[]string{"AddrA"},
		[]*services.SolanaAccountInfo{{Lamports: 42, Owner: "OwnerA", Data: []any{"AA==", "base64"}}},
	)
	if !witness.Complete {
		t.Fatalf("fixture witness incomplete: %#v", witness)
	}
	return input, assessment, witness
}

func configureGuardPermitSigner(t *testing.T, requireStateWitness bool) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	if requireStateWitness {
		t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "true")
	} else {
		t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "false")
	}
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "guard-live-test")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(seed))
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS", "90")
}

func TestFinishTransactionGuardV3ResponseIssuesStateBoundPermitV2(t *testing.T) {
	configureGuardPermitSigner(t, true)
	input, assessment, witness := completeGuardResponseFixture(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/shield/transaction", nil)

	(&Handler{}).finishTransactionGuardV3ResponseWithWitness(
		recorder,
		request,
		input,
		"req-state-live",
		time.Now(),
		assessment,
		transactionGuardProgramPolicy{Complete: true},
		transactionGuardIntentPolicy{Complete: true, Accounts: []transactionGuardAccountDelta{}},
		transactionGuardDecodedTransaction{Complete: true},
		transactionGuardThreatHistoryAnalysis{},
		transactionGuardCPIFlowAnalysis{},
		transactionGuardAuthoritySurfaceAnalysis{},
		witness,
		"",
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["action"] != "allow" || response["state_witness_complete"] != true || response["enforcement_permit_issued"] != true {
		t.Fatalf("unexpected response: %#v", response)
	}
	state, ok := response["state_witness"].(map[string]any)
	if !ok || state["binding_hash"] != witness.BindingHash || state["account_root_sha256"] != witness.AccountRoot {
		t.Fatalf("state witness missing from response: %#v", response["state_witness"])
	}
	permit, ok := response["enforcement_permit"].(map[string]any)
	if !ok || permit["version"] != transactionGuardStateBoundPermitVersion {
		t.Fatalf("state-bound permit missing: %#v", response["enforcement_permit"])
	}
	claims, ok := permit["claims"].(map[string]any)
	if !ok || claims["state_witness_hash"] != witness.BindingHash || claims["state_account_root_sha256"] != witness.AccountRoot {
		t.Fatalf("permit does not bind witness: %#v", permit)
	}
}

func TestFinishTransactionGuardV3ResponseKeepsPermitV1WhenWitnessNotRequired(t *testing.T) {
	configureGuardPermitSigner(t, false)
	input, assessment, witness := completeGuardResponseFixture(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/shield/transaction", nil)

	(&Handler{}).finishTransactionGuardV3ResponseWithWitness(
		recorder,
		request,
		input,
		"req-state-compat",
		time.Now(),
		assessment,
		transactionGuardProgramPolicy{Complete: true},
		transactionGuardIntentPolicy{Complete: true, Accounts: []transactionGuardAccountDelta{}},
		transactionGuardDecodedTransaction{Complete: true},
		transactionGuardThreatHistoryAnalysis{},
		transactionGuardCPIFlowAnalysis{},
		transactionGuardAuthoritySurfaceAnalysis{},
		witness,
		"",
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	permit := response["enforcement_permit"].(map[string]any)
	if permit["version"] != transactionGuardEnforcementPermitVersion {
		t.Fatalf("legacy permit compatibility changed: %#v", permit)
	}
}

func TestFinishTransactionGuardV3ResponseWithholdsWhenRequiredWitnessMissing(t *testing.T) {
	configureGuardPermitSigner(t, true)
	input, assessment, _ := completeGuardResponseFixture(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/shield/transaction", nil)
	missingWitness := unavailableTransactionGuardStateWitness(transactionFingerprint(input.Transaction), 901, "No bounded pre-state account set was available for state witnessing.")

	(&Handler{}).finishTransactionGuardV3ResponseWithWitness(
		recorder,
		request,
		input,
		"req-state-missing",
		time.Now(),
		assessment,
		transactionGuardProgramPolicy{Complete: true},
		transactionGuardIntentPolicy{Complete: true, Accounts: []transactionGuardAccountDelta{}},
		transactionGuardDecodedTransaction{Complete: true},
		transactionGuardThreatHistoryAnalysis{},
		transactionGuardCPIFlowAnalysis{},
		transactionGuardAuthoritySurfaceAnalysis{},
		missingWitness,
		"",
	)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d body=%s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["action"] != "withhold" || response["enforcement_permit_issued"] != false || response["enforcement_permit_status"] != "state_witness_unavailable" {
		t.Fatalf("missing state witness did not fail closed: %#v", response)
	}
}
