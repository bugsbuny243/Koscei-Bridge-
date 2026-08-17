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

// VerifyAndForwardSafeTransaction is the production Safe forwarding boundary.
// Hash authority is intentionally not injectable here: this boundary always
// uses Koschei's native Safe EIP-712 implementation so a caller cannot replace
// local recomputation with a Transaction Service supplied or pass-through hash.
// A BLOCK decision never calls the forwarder.
func VerifyAndForwardSafeTransaction(
	ctx context.Context,
	proof Proof,
	req SafeForwardRequest,
	forwarder SafeForwarder,
) (SigningGateResult, error) {
	if forwarder == nil {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}, ErrSigningBlocked
	}

	decision := AuthorizeSafeForward(proof, req, NativeSafeTxHashComputer{})
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
