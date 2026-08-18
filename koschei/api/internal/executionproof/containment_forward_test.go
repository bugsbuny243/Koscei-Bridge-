package executionproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"koschei/api/internal/matrixcontainment"
)

func containmentFixture(t *testing.T, req SafeForwardRequest, proof Proof) matrixcontainment.Receipt {
	t.Helper()
	blockHash := "1111111111111111111111111111111111111111111111111111111111111111"
	runnerHash := "5555555555555555555555555555555555555555555555555555555555555555"
	preStateHash := "6666666666666666666666666666666666666666666666666666666666666666"
	postStateHash := "7777777777777777777777777777777777777777777777777777777777777777"
	effectSetHash := "8888888888888888888888888888888888888888888888888888888888888888"

	computedSafeHash, err := (NativeSafeTxHashComputer{}).ComputeSafeTxHash(req.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	action, err := CanonicalSafeActionArtifact(req.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	calldataDigest := sha256.Sum256(req.Transaction.Data)

	receipt, err := matrixcontainment.Evaluate(matrixcontainment.CellInput{
		ChainID:                req.Transaction.ChainID,
		BlockNumber:            23456789,
		BlockHash:              blockHash,
		Target:                 req.Transaction.To,
		ApprovedIntentSHA256:   strings.TrimPrefix(proof.Envelope.Authorization.ApprovedSigningRequestID, "0x"),
		CandidateIntentSHA256:  strings.TrimPrefix(computedSafeHash, "0x"),
		ApprovedPayloadSHA256:  proof.Envelope.Payload.ApprovedCalldataSHA256,
		CandidatePayloadSHA256: hex.EncodeToString(calldataDigest[:]),
		ActionSHA256:           action.SHA256(),
		InvariantSetSHA256:     proof.Envelope.Simulation.InvariantSetSHA256,
		ApprovedRunnerSHA256:   runnerHash,
	}, matrixcontainment.Observation{
		BackendAvailable:           true,
		ObservedChainID:            req.Transaction.ChainID,
		ObservedBlockNumber:        23456789,
		ObservedBlockHash:          blockHash,
		ObservedRunnerSHA256:       runnerHash,
		PreStateSHA256:             preStateHash,
		PostStateSHA256:            postStateHash,
		EffectSetSHA256:            effectSetHash,
		AuthorityPreserved:         true,
		AssetBoundsPreserved:       true,
		CodeIntegrityPreserved:     true,
		ExecutionPathFullyObserved: true,
		InvariantsPass:             true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != matrixcontainment.DecisionRelease || !matrixcontainment.Verify(receipt) {
		t.Fatalf("fixture is not verified RELEASE: decision=%s reasons=%v", receipt.Decision, receipt.Reasons)
	}
	return receipt
}

func TestVerifyContainmentAndForwardSafeTransactionForwardsOnlyExactVerifiedRelease(t *testing.T) {
	req, proof := nativeSafeForwardFixture(t)
	receipt := containmentFixture(t, req, proof)
	forwarder := &recordingSafeForwarder{}

	got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), receipt, proof, req, forwarder)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != DecisionAllow {
		t.Fatalf("decision=%s reasons=%v", got.Decision, got.Reasons)
	}
	if forwarder.calls != 1 {
		t.Fatalf("forward calls=%d, want 1", forwarder.calls)
	}
}

func TestVerifyContainmentAndForwardSafeTransactionRejectsReleaseForDifferentTarget(t *testing.T) {
	req, proof := nativeSafeForwardFixture(t)
	release := containmentFixture(t, req, proof)
	input := release.Input
	input.Target = "0x9999999999999999999999999999999999999999"
	unrelatedRelease, err := matrixcontainment.Evaluate(input, release.Observation)
	if err != nil {
		t.Fatal(err)
	}
	if unrelatedRelease.Decision != matrixcontainment.DecisionRelease || !matrixcontainment.Verify(unrelatedRelease) {
		t.Fatalf("fixture must remain a structurally valid RELEASE")
	}
	forwarder := &recordingSafeForwarder{}

	got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), unrelatedRelease, proof, req, forwarder)
	if !errors.Is(err, ErrContainmentBlocked) {
		t.Fatalf("error=%v, want ErrContainmentBlocked", err)
	}
	if got.Decision != DecisionBlock || forwarder.calls != 0 {
		t.Fatalf("unrelated release escaped: decision=%s calls=%d", got.Decision, forwarder.calls)
	}
}

func TestVerifyContainmentAndForwardSafeTransactionRejectsReleaseForDifferentProof(t *testing.T) {
	req, proof := nativeSafeForwardFixture(t)
	receipt := containmentFixture(t, req, proof)
	otherProof := proof
	otherProof.Envelope.Simulation.InvariantSetSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	recomputed, err := Evaluate(otherProof.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	otherProof = recomputed
	forwarder := &recordingSafeForwarder{}

	got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), receipt, otherProof, req, forwarder)
	if !errors.Is(err, ErrContainmentBlocked) {
		t.Fatalf("error=%v, want ErrContainmentBlocked", err)
	}
	if got.Decision != DecisionBlock || forwarder.calls != 0 {
		t.Fatalf("proof mismatch escaped: decision=%s calls=%d", got.Decision, forwarder.calls)
	}
}

func TestVerifyContainmentAndForwardSafeTransactionNeverForwardsContain(t *testing.T) {
	req, proof := nativeSafeForwardFixture(t)
	release := containmentFixture(t, req, proof)
	input := release.Input
	input.CandidatePayloadSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contained, err := matrixcontainment.Evaluate(input, release.Observation)
	if err != nil {
		t.Fatal(err)
	}
	if contained.Decision != matrixcontainment.DecisionContain {
		t.Fatalf("containment decision=%s, want CONTAIN", contained.Decision)
	}
	forwarder := &recordingSafeForwarder{}

	got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), contained, proof, req, forwarder)
	if !errors.Is(err, ErrContainmentBlocked) {
		t.Fatalf("error=%v, want ErrContainmentBlocked", err)
	}
	if got.Decision != DecisionBlock || forwarder.calls != 0 {
		t.Fatalf("contain path escaped: decision=%s calls=%d", got.Decision, forwarder.calls)
	}
}

func TestVerifyContainmentAndForwardSafeTransactionNeverForwardsUnavailable(t *testing.T) {
	req, proof := nativeSafeForwardFixture(t)
	release := containmentFixture(t, req, proof)
	unavailable, err := matrixcontainment.Evaluate(release.Input, matrixcontainment.Observation{BackendAvailable: false})
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.Decision != matrixcontainment.DecisionUnavailable {
		t.Fatalf("containment decision=%s, want UNAVAILABLE", unavailable.Decision)
	}
	forwarder := &recordingSafeForwarder{}

	got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), unavailable, proof, req, forwarder)
	if !errors.Is(err, ErrContainmentBlocked) {
		t.Fatalf("error=%v, want ErrContainmentBlocked", err)
	}
	if got.Decision != DecisionBlock || forwarder.calls != 0 {
		t.Fatalf("unavailable path escaped: decision=%s calls=%d", got.Decision, forwarder.calls)
	}
}

func TestVerifyContainmentAndForwardSafeTransactionRejectsTamperedReceipt(t *testing.T) {
	req, proof := nativeSafeForwardFixture(t)
	receipt := containmentFixture(t, req, proof)
	receipt.Observation.AuthorityPreserved = false
	forwarder := &recordingSafeForwarder{}

	got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), receipt, proof, req, forwarder)
	if !errors.Is(err, ErrContainmentBlocked) {
		t.Fatalf("error=%v, want ErrContainmentBlocked", err)
	}
	if got.Decision != DecisionBlock || forwarder.calls != 0 {
		t.Fatalf("tampered receipt escaped: decision=%s calls=%d", got.Decision, forwarder.calls)
	}
}
