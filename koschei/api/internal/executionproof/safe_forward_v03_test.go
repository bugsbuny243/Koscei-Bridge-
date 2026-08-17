package executionproof

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func safeForkFixture(t *testing.T) (SafeForwardRequest, Proof, VerifiedForkRequest, VerifiedForkBackendResult) {
	t.Helper()
	req, proof := nativeSafeForwardFixture(t)
	forkReq := validVerifiedForkRequest()
	forkReq.ChainID = req.Transaction.ChainID
	forkReq.Payload = EVMPayload{
		From:     req.Transaction.Safe,
		To:       req.Transaction.To,
		ValueHex: "0x0",
		DataHex:  "0x",
	}
	prepared, ok := prepareVerifiedForkRequest(forkReq)
	if !ok {
		t.Fatal("safe fork request did not prepare")
	}
	proof.Envelope.Simulation.InvariantSetSHA256 = prepared.Simulation.InvariantSetSHA256
	var err error
	proof, err = Evaluate(proof.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	result := validVerifiedForkBackendResult(t, forkReq)
	result.Execution = ForkExecutionEvidence{
		TransactionHash:          "0x" + strings.Repeat("3", 64),
		TransactionReceiptSHA256: strings.Repeat("4", 64),
		InvariantEvidenceSHA256:  canonicalInvariantEvidenceDigest(result.Simulation.Checks),
	}
	return req, proof, forkReq, result
}

func TestVerifyForkAndForwardSafeTransactionRequiresMatchingVerifiedExecution(t *testing.T) {
	req, proof, forkReq, result := safeForkFixture(t)
	forwarder := &recordingSafeForwarder{}
	backend := fixedVerifiedForkBackend{result: result}

	decision, receipt, err := VerifyForkAndForwardSafeTransaction(context.Background(), proof, forkReq, backend, req, forwarder)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionAllow || !ValidVerifiedForkReceipt(receipt) {
		t.Fatalf("decision=%s receipt_valid=%v reasons=%v", decision.Decision, ValidVerifiedForkReceipt(receipt), decision.Reasons)
	}
	if forwarder.calls != 1 {
		t.Fatalf("forward calls=%d want=1", forwarder.calls)
	}
}

func TestVerifyForkAndForwardSafeTransactionBlocksDifferentSimulatedPayload(t *testing.T) {
	req, proof, forkReq, result := safeForkFixture(t)
	forkReq.Payload.To = "0x2222222222222222222222222222222222222222"
	forwarder := &recordingSafeForwarder{}

	decision, _, err := VerifyForkAndForwardSafeTransaction(context.Background(), proof, forkReq, fixedVerifiedForkBackend{result: result}, req, forwarder)
	if !errors.Is(err, ErrSigningBlocked) {
		t.Fatalf("error=%v want ErrSigningBlocked", err)
	}
	assertSigningBlockedFor(t, decision, ReasonForkPayloadMismatch)
	if forwarder.calls != 0 {
		t.Fatalf("mismatched fork payload reached forwarder: calls=%d", forwarder.calls)
	}
}

func TestVerifyForkAndForwardSafeTransactionBlocksInvalidExecutionEvidence(t *testing.T) {
	req, proof, forkReq, result := safeForkFixture(t)
	result.Execution.InvariantEvidenceSHA256 = strings.Repeat("9", 64)
	forwarder := &recordingSafeForwarder{}

	decision, _, err := VerifyForkAndForwardSafeTransaction(context.Background(), proof, forkReq, fixedVerifiedForkBackend{result: result}, req, forwarder)
	if !errors.Is(err, ErrSigningBlocked) {
		t.Fatalf("error=%v want ErrSigningBlocked", err)
	}
	assertSigningBlockedFor(t, decision, ReasonForkExecutionRequired)
	if forwarder.calls != 0 {
		t.Fatalf("invalid execution evidence reached forwarder: calls=%d", forwarder.calls)
	}
}

func TestValidVerifiedForkReceiptRejectsTamperedOuterDigest(t *testing.T) {
	_, _, forkReq, result := safeForkFixture(t)
	receipt, err := RunVerifiedForkExecution(context.Background(), forkReq, fixedVerifiedForkBackend{result: result})
	if err != nil {
		t.Fatal(err)
	}
	receipt.Execution.TransactionHash = "0x" + strings.Repeat("8", 64)
	if ValidVerifiedForkReceipt(receipt) {
		t.Fatal("tampered execution transaction hash remained valid")
	}
}
