package executionproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"koschei/api/internal/matrixcontainment"
)

var ErrContainmentBlocked = errors.New("containment gate blocked Safe signing request")

// VerifyContainmentAndForwardSafeTransaction composes the defensive containment
// receipt with the existing Execution Proof Safe forwarding boundary.
//
// A serialized RELEASE is never sufficient. The receipt must verify by full
// recomputation and must bind to the exact Safe request and the exact approved
// Execution Proof evidence. This prevents a valid RELEASE receipt for one Safe
// transaction from being replayed to authorize a different transaction.
func VerifyContainmentAndForwardSafeTransaction(
	ctx context.Context,
	receipt matrixcontainment.Receipt,
	proof Proof,
	req SafeForwardRequest,
	forwarder SafeForwarder,
) (SigningGateResult, error) {
	if !containmentBindsExactSafeRequest(receipt, proof, req) {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}, ErrContainmentBlocked
	}

	return VerifyAndForwardSafeTransaction(ctx, proof, req, forwarder)
}

func containmentBindsExactSafeRequest(receipt matrixcontainment.Receipt, proof Proof, req SafeForwardRequest) bool {
	if !matrixcontainment.Verify(receipt) || receipt.Decision != matrixcontainment.DecisionRelease {
		return false
	}
	if !validSafeTransaction(req.Transaction) || !validHex32(req.PresentedSafeHash) {
		return false
	}

	computedSafeHash, err := (NativeSafeTxHashComputer{}).ComputeSafeTxHash(req.Transaction)
	if err != nil || !equalHex32(computedSafeHash, req.PresentedSafeHash) {
		return false
	}
	action, err := CanonicalSafeActionArtifact(req.Transaction)
	if err != nil {
		return false
	}

	calldataDigest := sha256.Sum256(req.Transaction.Data)
	candidatePayload := hex.EncodeToString(calldataDigest[:])

	input := receipt.Input
	return input.ChainID == req.Transaction.ChainID &&
		strings.EqualFold(strings.TrimSpace(input.Target), strings.TrimSpace(req.Transaction.To)) &&
		equalHex32(input.ApprovedIntentSHA256, proof.Envelope.Authorization.ApprovedSigningRequestID) &&
		equalHex32(input.CandidateIntentSHA256, computedSafeHash) &&
		equalDigest(input.ApprovedPayloadSHA256, proof.Envelope.Payload.ApprovedCalldataSHA256) &&
		equalDigest(input.CandidatePayloadSHA256, candidatePayload) &&
		equalDigest(input.ActionSHA256, action.SHA256()) &&
		equalDigest(input.InvariantSetSHA256, proof.Envelope.Simulation.InvariantSetSHA256)
}
