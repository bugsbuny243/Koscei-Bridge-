package executionproof

import (
    "context"
    "errors"

    "koschei/api/internal/matrixcontainment"
)

var ErrContainmentBlocked = errors.New("containment gate blocked Safe signing request")

// VerifyContainmentAndForwardSafeTransaction composes the defensive containment
// receipt with the existing Execution Proof Safe forwarding boundary.
//
// The containment receipt is never trusted as serialized authority: it must
// verify by full recomputation and must carry RELEASE. CONTAIN and UNAVAILABLE
// are terminal fail-closed outcomes and the side-effecting forwarder is not
// invoked.
func VerifyContainmentAndForwardSafeTransaction(
    ctx context.Context,
    receipt matrixcontainment.Receipt,
    proof Proof,
    req SafeForwardRequest,
    forwarder SafeForwarder,
) (SigningGateResult, error) {
    if !matrixcontainment.Verify(receipt) || receipt.Decision != matrixcontainment.DecisionRelease {
        return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}, ErrContainmentBlocked
    }

    return VerifyAndForwardSafeTransaction(ctx, proof, req, forwarder)
}
