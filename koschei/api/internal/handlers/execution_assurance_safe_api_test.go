package handlers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/executionproof"
	"koschei/api/internal/securityevidence"
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
	if !response.AttestationVerified || response.AttestationProducer != safeExecutionAssuranceTestProducer {
		t.Fatalf("trusted attestation was not verified: %+v", response)
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
	if !response.AttestationVerified {
		t.Fatalf("valid proof attestation should remain independently verified: %+v", response)
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
		!containsSafeExecutionAssuranceReason(response.ReasonCodes, executionproof.ReasonProofHashMismatch) ||
		!containsSafeExecutionAssuranceReason(response.ReasonCodes, executionproof.ReasonUntrustedAttestation) {
		t.Fatalf("tampered proof reasons missing: %+v", response)
	}
	if response.AttestationVerified {
		t.Fatalf("attestation binding survived proof tampering: %+v", response)
	}
	if strings.EqualFold(response.PresentedEnvelopeSHA256, response.RecomputedEnvelopeSHA256) {
		t.Fatalf("tampered envelope digest unexpectedly matched: %+v", response)
	}
}

func TestSafeExecutionAssuranceV1BlocksSelfSignedInternallyConsistentProof(t *testing.T) {
	request := safeExecutionAssuranceTestRequest(t)
	attackerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	request.ProofAttestation = signSafeExecutionAssuranceTestAttestation(t, request, attackerKey, time.Now().UTC().Add(-30*time.Second), time.Now().UTC().Add(-time.Second))

	recorder := executeSafeExecutionAssuranceRequest(t, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response safeExecutionAssuranceAPIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Decision != executionproof.DecisionBlock || !containsSafeExecutionAssuranceReason(response.ReasonCodes, executionproof.ReasonUntrustedAttestation) {
		t.Fatalf("attacker-signed internally consistent proof was not blocked: %+v", response)
	}
	if response.AttestationVerified {
		t.Fatalf("attacker attestation was marked verified: %+v", response)
	}
}

func TestSafeExecutionAssuranceV1BlocksStaleTrustedAttestation(t *testing.T) {
	request := safeExecutionAssuranceTestRequest(t)
	privateKey := safeExecutionAssuranceTestPrivateKey()
	now := time.Now().UTC()
	request.ProofAttestation = signSafeExecutionAssuranceTestAttestation(t, request, privateKey, now.Add(-7*time.Minute), now.Add(-6*time.Minute))

	recorder := executeSafeExecutionAssuranceRequest(t, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response safeExecutionAssuranceAPIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Decision != executionproof.DecisionBlock || !containsSafeExecutionAssuranceReason(response.ReasonCodes, executionproof.ReasonStaleAttestation) {
		t.Fatalf("stale trusted attestation did not fail closed: %+v", response)
	}
	if response.AttestationVerified {
		t.Fatalf("stale attestation was marked verified: %+v", response)
	}
}

func TestSafeExecutionAssuranceV1FailsClosedWhenTrustAnchorMissing(t *testing.T) {
	request := safeExecutionAssuranceTestRequest(t)
	t.Setenv("KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_PRODUCER", "")
	t.Setenv("KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_ED25519_PUBLIC_KEY", "")

	recorder := executeSafeExecutionAssuranceRequest(t, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "execution_assurance_unconfigured") {
		t.Fatalf("missing unconfigured failure code: %s", recorder.Body.String())
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

const safeExecutionAssuranceTestProducer = "test-independent-collector"

func safeExecutionAssuranceTestRequest(t *testing.T) safeExecutionAssuranceAPIRequest {
	t.Helper()
	privateKey := safeExecutionAssuranceTestPrivateKey()
	t.Setenv("KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_PRODUCER", safeExecutionAssuranceTestProducer)
	t.Setenv("KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_ED25519_PUBLIC_KEY", base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)))

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

	request := safeExecutionAssuranceAPIRequest{
		ExecutionProof:      proof,
		Transaction:         transaction,
		PresentedSafeTxHash: computedSafeTxHash,
	}
	now := time.Now().UTC()
	request.ProofAttestation = signSafeExecutionAssuranceTestAttestation(t, request, privateKey, now.Add(-30*time.Second), now.Add(-time.Second))
	return request
}

func signSafeExecutionAssuranceTestAttestation(t *testing.T, request safeExecutionAssuranceAPIRequest, privateKey ed25519.PrivateKey, from, to time.Time) securityevidence.Event {
	t.Helper()
	decoded, err := decodeSafeExecutionAssuranceTransaction(request.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	computedSafeTxHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(decoded)
	if err != nil {
		t.Fatal(err)
	}
	recomputedProof, err := executionproof.Evaluate(request.ExecutionProof.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	binding := executionproof.SafeExecutionAttestationBindingV1{
		ChainID:              decoded.ChainID,
		Safe:                 decoded.Safe,
		SafeTxHash:           computedSafeTxHash,
		ExecutionProofSHA256: recomputedProof.EnvelopeSHA256,
	}
	bindingDigest, err := executionproof.SafeExecutionAttestationBindingDigestV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBinding, err := binding.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer: safeExecutionAssuranceTestProducer,
		Subject: securityevidence.Subject{
			Chain: fmt.Sprintf("eip155:%d", canonicalBinding.ChainID),
			Type:  executionproof.SafeExecutionAttestationSubjectTypeV1,
			ID:    canonicalBinding.SafeTxHash,
		},
		Window: securityevidence.ObservationWindow{
			FromUnixMS: from.UnixMilli(),
			ToUnixMS:   to.UnixMilli(),
		},
		SourceDigests: []string{canonicalBinding.ExecutionProofSHA256},
		Findings: []securityevidence.Finding{{
			ID:             executionproof.SafeExecutionAttestationFindingIDV1,
			Kind:           executionproof.SafeExecutionAttestationFindingKindV1,
			State:          securityevidence.StateVerified,
			EvidenceSHA256: bindingDigest,
		}},
	}).SignEd25519(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func safeExecutionAssuranceTestPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}

func containsSafeExecutionAssuranceReason(reasons []executionproof.ReasonCode, target executionproof.ReasonCode) bool {
	for _, reason := range reasons {
		if reason == target {
			return true
		}
	}
	return false
}
