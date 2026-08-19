package executionproof

import (
	"context"
	"testing"

	"koschei/api/internal/matrixcontainment"
)

type stubSafeIsolatedBackend struct {
	evidence SafeExecutionEvidence
	err      error
}

func (b stubSafeIsolatedBackend) ExecuteSafe(context.Context, matrixcontainment.CellInput, SafeTransaction) (SafeExecutionEvidence, error) {
	return b.evidence, b.err
}

func safeRunnerFixture(t *testing.T) (matrixcontainment.CellInput, matrixcontainment.ActionArtifact, SafeContainmentPolicy, SafeExecutionEvidence) {
	t.Helper()
	req := validSafeForwardRequest()
	action, err := CanonicalSafeActionArtifact(req.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	policy := SafeContainmentPolicy{
		Version:        SafeContainmentPolicyVersion,
		Safe:           req.Transaction.Safe,
		AllowedOutflow: []SafeOutflowBound{{Kind: "native", To: req.Transaction.To, MaxAmount: "1000"}},
	}
	policyHash, err := safeContainmentPolicySHA256(policy)
	if err != nil {
		t.Fatal(err)
	}

	zero := "0x0000000000000000000000000000000000000000"
	authority := SafeAuthoritySnapshot{
		Owners: []string{"0x1111111111111111111111111111111111111111"}, Threshold: 1,
		Guard: zero, FallbackHandler: zero,
		Implementation: "0x2222222222222222222222222222222222222222",
		CodeHash:       "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	input := matrixcontainment.CellInput{
		ChainID: req.Transaction.ChainID, BlockNumber: 23456789,
		BlockHash:              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Target:                 req.Transaction.To,
		ApprovedIntentSHA256:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CandidateIntentSHA256:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ApprovedPayloadSHA256:  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		CandidatePayloadSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ActionSHA256:           action.SHA256(), InvariantSetSHA256: policyHash,
		ApprovedRunnerSHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
	evidence := SafeExecutionEvidence{
		ChainID: req.Transaction.ChainID, BlockNumber: input.BlockNumber, BlockHash: "0x" + input.BlockHash,
		RunnerSHA256:    input.ApprovedRunnerSHA256,
		PreStateSHA256:  "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		PostStateSHA256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		EffectSetSHA256: "9999999999999999999999999999999999999999999999999999999999999999",
		Before:          authority, After: authority,
		Trace: validSafeTraceFixture(req.Transaction.Safe, req.Transaction.To),
	}
	return input, action, policy, evidence
}

func TestSafeIsolatedRunnerVerifiedEvidenceCanRelease(t *testing.T) {
	input, action, policy, evidence := safeRunnerFixture(t)
	runner := SafeIsolatedRunner{Backend: stubSafeIsolatedBackend{evidence: evidence}, Policy: policy}
	receipt, err := matrixcontainment.EvaluateWithRunner(context.Background(), input, action, runner)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != matrixcontainment.DecisionRelease {
		t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons)
	}
}

func TestSafeIsolatedRunnerContainsAuthorityChange(t *testing.T) {
	input, action, policy, evidence := safeRunnerFixture(t)
	evidence.After.Owners = []string{"0x3333333333333333333333333333333333333333"}
	runner := SafeIsolatedRunner{Backend: stubSafeIsolatedBackend{evidence: evidence}, Policy: policy}
	receipt, err := matrixcontainment.EvaluateWithRunner(context.Background(), input, action, runner)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != matrixcontainment.DecisionContain {
		t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons)
	}
}

func TestSafeIsolatedRunnerContainsUnapprovedOutflow(t *testing.T) {
	input, action, policy, evidence := safeRunnerFixture(t)
	evidence.AssetMovements = []SafeAssetMovement{{Kind: "native", From: policy.Safe, To: "0x9999999999999999999999999999999999999999", Amount: "1"}}
	runner := SafeIsolatedRunner{Backend: stubSafeIsolatedBackend{evidence: evidence}, Policy: policy}
	receipt, err := matrixcontainment.EvaluateWithRunner(context.Background(), input, action, runner)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != matrixcontainment.DecisionContain {
		t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons)
	}
}

func TestSafeIsolatedRunnerRejectsTruncatedTraceAsUnavailable(t *testing.T) {
	input, action, policy, evidence := safeRunnerFixture(t)
	evidence.Trace.Truncated = true
	evidence.Trace.TraceSHA256 = safeTraceDigest(evidence.Trace)
	runner := SafeIsolatedRunner{Backend: stubSafeIsolatedBackend{evidence: evidence}, Policy: policy}
	receipt, err := matrixcontainment.EvaluateWithRunner(context.Background(), input, action, runner)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != matrixcontainment.DecisionUnavailable {
		t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons)
	}
}

func TestSafeIsolatedRunnerRejectsForgedTraceDigestAsUnavailable(t *testing.T) {
	input, action, policy, evidence := safeRunnerFixture(t)
	evidence.Trace.TraceSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runner := SafeIsolatedRunner{Backend: stubSafeIsolatedBackend{evidence: evidence}, Policy: policy}
	receipt, err := matrixcontainment.EvaluateWithRunner(context.Background(), input, action, runner)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != matrixcontainment.DecisionUnavailable {
		t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons)
	}
}

func TestSafeIsolatedRunnerPolicyIdentityMismatchIsUnavailable(t *testing.T) {
	input, action, policy, evidence := safeRunnerFixture(t)
	policy.AllowedOutflow[0].MaxAmount = "999"
	runner := SafeIsolatedRunner{Backend: stubSafeIsolatedBackend{evidence: evidence}, Policy: policy}
	receipt, err := matrixcontainment.EvaluateWithRunner(context.Background(), input, action, runner)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != matrixcontainment.DecisionUnavailable {
		t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons)
	}
}
