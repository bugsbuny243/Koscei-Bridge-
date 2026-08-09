package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTransactionValueEvidenceIsExposedWithoutChangingGuardDecision(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "false")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "false")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", "")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "")

	input := transactionGuardV2Request{
		Transaction: "value-evidence-response-fixture",
		Encoding:    "base64",
		Network:     "solana-mainnet",
		Wallet:      "WalletA",
	}
	assessment := transactionFirewallAssessment{
		Action:       "allow",
		RiskLevel:    "low",
		RiskIndex:    7,
		SimulationOK: true,
		Findings:     []transactionFirewallFinding{},
		Logs:         []string{},
	}
	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		TokenOperations: []transactionGuardDecodedTokenOperation{
			{Kind: "transfer", ProgramID: guardV3SPLTokenProgramID, Source: "UnknownSource", Destination: "UnknownDestination", AmountRaw: "9", Authority: "WalletA"},
		},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{Requested: false},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/shield/transaction", nil)

	(&Handler{}).finishTransactionGuardV3ResponseWithWitness(
		recorder,
		request,
		input,
		"req-value-evidence",
		time.Now(),
		assessment,
		transactionGuardProgramPolicy{Complete: true},
		transactionGuardIntentPolicy{Complete: true, Accounts: []transactionGuardAccountDelta{}},
		decoded,
		transactionGuardThreatHistoryAnalysis{},
		transactionGuardCPIFlowAnalysis{},
		transactionGuardAuthoritySurfaceAnalysis{},
		unavailableTransactionGuardStateWitness(transactionFingerprint(input.Transaction), 0, "not required for this response test"),
		"",
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Action                           string                        `json:"action"`
		RiskIndex                        int                           `json:"risk_index"`
		GuardComplete                    bool                          `json:"guard_complete"`
		TransactionValueEvidenceComplete bool                          `json:"transaction_value_evidence_complete"`
		TransactionValueEvidence         transactionGuardValueEvidence `json:"transaction_value_evidence"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Action != "allow" || body.RiskIndex != 7 || !body.GuardComplete {
		t.Fatalf("Value Evidence changed Guard decision: %#v", body)
	}
	if body.TransactionValueEvidenceComplete || body.TransactionValueEvidence.Complete || body.TransactionValueEvidence.Status != "partial" {
		t.Fatalf("Value Evidence did not fail closed independently: %#v", body.TransactionValueEvidence)
	}
	if body.TransactionValueEvidence.PolicyUseStatus != "evidence_only_not_enforced" || body.TransactionValueEvidence.EvidenceHashSHA256 == "" {
		t.Fatalf("Value Evidence contract incomplete: %#v", body.TransactionValueEvidence)
	}
}
