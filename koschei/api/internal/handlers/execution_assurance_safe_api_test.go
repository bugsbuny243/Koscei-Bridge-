package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"koschei/api/internal/executionproof"
)

func TestSafeExecutionAssuranceV1AllowsExactVerifiedSafeRequest(t *testing.T) {
	request := safeExecutionAssuranceTestRequest(t)
	recorder := executeSafeExecutionAssuranceRequest(t, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var response safeExecutionAssuranceAPIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Decision != executionproof.DecisionAllow {
		t.Fatalf("unexpected decision: %+v", response)
	}
	if response.ComputedSafeTxHash == "" || !strings.EqualFold(response.ComputedSafeTxHash, request.PresentedSafeTxHash) {
		t.Fatalf("safe hash was not independently reproduced: %+v", response)
	}
	if response.RecomputedEnvelopeSHA256 == "" || !strings.EqualFold(response.RecomputedEnvelopeSHA256, request.ExecutionProof.EnvelopeSHA256) {
		t.Fatalf("proof envelope was not independently reproduced: %+v", response)
	}
	if response.MainnetTransactionSent || response.SigningAuthority || response.ForwardingAuthority || response.ProductionControlMutation {
		t.Fatalf("verification endpoint exposed forbidden authority: %+v", response)
	}
}

func TestSafeExecutionAssuranceV1BlocksPresentedSafeHashMismatch(t *testing.T) {
	request := safeExecutionAssuranceTestRequest(t)
	request.PresentedSafeTxHash = "0x" + strings.Repeat("f", 64)

	recorder := executeSafeExecutionAssuranceRequest(t, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response safeExecutionAssuranceAPIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Decision != executionproof.DecisionBlock || !containsSafeExecutionAssuranceReason(response.ReasonCodes, executionproof.ReasonSafeHashMismatch) {
		t.Fatalf("hash mismatch did not fail closed: %+v", response)
	}
	if strings.EqualFold(response.ComputedSafeTxHash, request.PresentedSafeTxHash) {
		t.Fatalf("test fixture unexpectedly matched computed hash")
	}
}

func TestSafeExecutionAssuranceV1DoesNotTrustSerializedAllow(t *testing.T) {
	request := safeExecutionAssuranceTestRequest(t)
	request.ExecutionProof.Envelope.Payload.GeneratedCalldataSHA256 = strings.Repeat("e", 64)
	request.ExecutionProof.Evaluation = executionproof.Evaluation{Decision: executionproof.DecisionAllow}

	recorder := executeSafeExecutionAssuranceRequest(t, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response safeExecutionAssuranceAPIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Decision != executionproof.DecisionBlock {
		t.Fatalf("tampered proof was trusted: %+v", response)
	}
	if !containsSafeExecutionAssuranceReason(response.ReasonCodes, executionproof.ReasonPayloadMismatch) ||
		!containsSafeExecutionAssuranceReason(response.ReasonCodes, executionproof.ReasonProofHashMismatch) {
		t.Fatalf("tampered proof reasons missing: %+v", response)
	}
	if strings.EqualFold(response.PresentedEnvelopeSHA256, response.RecomputedEnvelopeSHA256) {
		t.Fatalf("tampered envelope digest unexpectedly matched: %+v", response)
	}
}

func TestSafeExecutionAssuranceV1RejectsInvalidUint256(t *testing.T) {
	request := safeExecutionAssuranceTestRequest(t)
	request.Transaction.Value = "-1"

	recorder := executeSafeExecutionAssuranceRequest(t, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalid_safe_transaction") {
		t.Fatalf("missing invalid transaction code: %s", recorder.Body.String())
	}
}

func executeSafeExecutionAssuranceRequest(t *testing.T, request safeExecutionAssuranceAPIRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/execution-assurance/safe/verify", strings.NewReader(string(body)))
	(&Handler{}).SafeExecutionAssuranceV1(recorder, httpRequest)
	return recorder
}

func safeExecutionAssuranceTestRequest(t *testing.T) safeExecutionAssuranceAPIRequest {
	t.Helper()
	transaction := safeExecutionAssuranceTransactionAPIInput{
		ChainID:        1,
		Safe:           "0x1111111111111111111111111111111111111111",
		To:             "0x2222222222222222222222222222222222222222",
		Value:          "0",
		Data:           "0x1234",
		Operation:      0,
		SafeTxGas:      "0",
		BaseGas:        "0",
		GasPrice:       "0",
		GasToken:       "0x0000000000000000000000000000000000000000",
		RefundReceiver: "0x0000000000000000000000000000000000000000",
		Nonce:          "7",
	}
	decoded, err := decodeSafeExecutionAssuranceTransaction(transaction)
	if err != nil {
		t.Fatal(err)
	}
	computedSafeTxHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(decoded)
	if err != nil {
		t.Fatal(err)
	}
	calldataDigest := sha256.Sum256(decoded.Data)
	calldataSHA256 := hex.EncodeToString(calldataDigest[:])
	digest := strings.Repeat("a", 64)

	proof, err := executionproof.Evaluate(executionproof.Envelope{
		Version: executionproof.Version,
		Source: executionproof.SourceEvidence{
			CommitID: strings.Repeat("1", 40),
			TreeID:   strings.Repeat("2", 40),
		},
		Build: executionproof.BuildEvidence{
			ToolchainSHA256:        strings.Repeat("3", 64),
			ApprovedArtifactSHA256: digest,
			BuiltArtifactSHA256:    digest,
		},
		Runtime: executionproof.RuntimeEvidence{
			ObservedArtifactSHA256: digest,
			PolicySHA256:           strings.Repeat("4", 64),
		},
		Payload: executionproof.PayloadEvidence{
			ChainID:                 decoded.ChainID,
			Target:                  decoded.To,
			ApprovedCalldataSHA256:  calldataSHA256,
			GeneratedCalldataSHA256: calldataSHA256,
			GeneratorSHA256:         strings.Repeat("5", 64),
		},
		Simulation: executionproof.SimulationEvidence{
			InvariantSetSHA256: strings.Repeat("6", 64),
			Result:             "PASS",
		},
		Authorization: executionproof.AuthorizationEvidence{
			SigningPolicySHA256:      strings.Repeat("7", 64),
			ApprovedSigningRequestID: computedSafeTxHash,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proof.Evaluation.Decision != executionproof.DecisionAllow {
		t.Fatalf("invalid test proof: %+v", proof.Evaluation)
	}

	return safeExecutionAssuranceAPIRequest{
		ExecutionProof:      proof,
		Transaction:         transaction,
		PresentedSafeTxHash: computedSafeTxHash,
	}
}

func containsSafeExecutionAssuranceReason(reasons []executionproof.ReasonCode, target executionproof.ReasonCode) bool {
	for _, reason := range reasons {
		if reason == target {
			return true
		}
	}
	return false
}
