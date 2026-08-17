package executionproof

import (
	"context"
	"errors"
)

// SafeForwarder is the only side-effecting boundary in the Safe path. Concrete
// adapters may propose/forward a transaction only after Koschei has recomputed
// the Safe transaction hash and returned ALLOW.
type SafeForwarder interface {
	ForwardSafeTransaction(ctx context.Context, req SafeForwardRequest) error
}

var ErrSigningBlocked = errors.New("execution proof blocked Safe signing request")

// VerifyAndForwardSafeTransaction enforces authorization before any external
// forwarding side effect. A BLOCK decision never calls the forwarder.
func VerifyAndForwardSafeTransaction(
	ctx context.Context,
	proof Proof,
	req SafeForwardRequest,
	computer SafeTxHashComputer,
	forwarder SafeForwarder,
) (SigningGateResult, error) {
	if forwarder == nil {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}, ErrSigningBlocked
	}

	decision := AuthorizeSafeForward(proof, req, computer)
	if decision.Decision != DecisionAllow {
		return decision, ErrSigningBlocked
	}

	if err := ctx.Err(); err != nil {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}, err
	}
	if err := forwarder.ForwardSafeTransaction(ctx, req); err != nil {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}, err
	}

	return decision, nil
}
