package executionproof

import (
	"strings"
)

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

// AuthorizeSigningRequest is intentionally provider-agnostic. A Safe/MPC adapter
// must call this before forwarding a signing request. It re-evaluates the proof
// and binds the external signing request to the proof payload.
func AuthorizeSigningRequest(proof Proof, req SigningRequest) SigningGateResult {
	auth := AuthorizeForSigning(proof)
	if auth.Decision != DecisionAllow {
		return SigningGateResult{Decision: DecisionBlock, Reasons: append([]ReasonCode(nil), auth.Reasons...)}
	}

	if req.ChainID == 0 || strings.TrimSpace(req.Target) == "" || !validSHA256(req.CalldataSHA256) || !validHexHash(req.SafeTxHash) {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}
	}

	if req.ChainID != proof.Envelope.Payload.ChainID ||
		!strings.EqualFold(strings.TrimSpace(req.Target), strings.TrimSpace(proof.Envelope.Payload.Target)) ||
		!equalDigest(req.CalldataSHA256, proof.Envelope.Payload.GeneratedCalldataSHA256) {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonSigningRequestMismatch}}
	}

	return SigningGateResult{Decision: DecisionAllow}
}

func validHexHash(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "0x")
	return validSHA256(v)
}
