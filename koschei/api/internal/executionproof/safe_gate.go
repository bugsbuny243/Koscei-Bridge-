package executionproof

import "strings"

type SigningRequest struct {
	ChainID        uint64
	Target         string
	CalldataSHA256 string
	SafeTxHash     string
}

type SigningGateResult struct {
	Decision Decision
	Reasons  []ReasonCode
}

const (
	ReasonSigningRequestMismatch ReasonCode = "EP-007-SIGNING-REQUEST-MISMATCH"
	ReasonInvalidSigningRequest  ReasonCode = "EP-008-INVALID-SIGNING-REQUEST"
)

// AuthorizeSigningRequest is the provider-agnostic enforcement boundary.
// A concrete Safe adapter MUST locally recompute SafeTxHash from the raw Safe
// transaction fields before calling this function; a transaction-service
// supplied hash alone is not authoritative. This function then re-evaluates
// the Execution Proof and requires exact identity with the pre-approved request.
func AuthorizeSigningRequest(proof Proof, req SigningRequest) SigningGateResult {
	auth := AuthorizeForSigning(proof)
	if auth.Decision != DecisionAllow {
		return SigningGateResult{Decision: DecisionBlock, Reasons: append([]ReasonCode(nil), auth.Reasons...)}
	}

	if req.ChainID == 0 || strings.TrimSpace(req.Target) == "" || !validSHA256(req.CalldataSHA256) || !validHex32(req.SafeTxHash) {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}
	}

	if req.ChainID != proof.Envelope.Payload.ChainID ||
		!strings.EqualFold(strings.TrimSpace(req.Target), strings.TrimSpace(proof.Envelope.Payload.Target)) ||
		!equalDigest(req.CalldataSHA256, proof.Envelope.Payload.GeneratedCalldataSHA256) ||
		!equalHex32(req.SafeTxHash, proof.Envelope.Authorization.ApprovedSigningRequestID) {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonSigningRequestMismatch}}
	}

	return SigningGateResult{Decision: DecisionAllow}
}

func equalHex32(a, b string) bool {
	a = strings.TrimPrefix(strings.TrimSpace(a), "0x")
	b = strings.TrimPrefix(strings.TrimSpace(b), "0x")
	return strings.EqualFold(a, b)
}
