package executionproof

import (
	"strings"
	"testing"
)

func validSigningRequest() SigningRequest {
	return SigningRequest{
		ChainID:        1,
		Target:         "0x1111111111111111111111111111111111111111",
		CalldataSHA256: digest('f'),
		SafeTxHash:     "0x" + strings.Repeat("4", 64),
	}
}

func TestAuthorizeSigningRequestAllowsMatchingProofAndRequest(t *testing.T) {
	proof, err := Evaluate(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	got := AuthorizeSigningRequest(proof, validSigningRequest())
	if got.Decision != DecisionAllow {
		t.Fatalf("decision = %s, reasons = %v", got.Decision, got.Reasons)
	}
}

func TestAuthorizeSigningRequestBlocksChainMismatch(t *testing.T) {
	proof, _ := Evaluate(validEnvelope())
	req := validSigningRequest()
	req.ChainID = 10
	assertSigningBlockedFor(t, AuthorizeSigningRequest(proof, req), ReasonSigningRequestMismatch)
}

func TestAuthorizeSigningRequestBlocksTargetMismatch(t *testing.T) {
	proof, _ := Evaluate(validEnvelope())
	req := validSigningRequest()
	req.Target = "0x2222222222222222222222222222222222222222"
	assertSigningBlockedFor(t, AuthorizeSigningRequest(proof, req), ReasonSigningRequestMismatch)
}

func TestAuthorizeSigningRequestBlocksCalldataMismatch(t *testing.T) {
	proof, _ := Evaluate(validEnvelope())
	req := validSigningRequest()
	req.CalldataSHA256 = strings.Repeat("5", 64)
	assertSigningBlockedFor(t, AuthorizeSigningRequest(proof, req), ReasonSigningRequestMismatch)
}

func TestAuthorizeSigningRequestBlocksSafeTxHashMismatch(t *testing.T) {
	proof, _ := Evaluate(validEnvelope())
	req := validSigningRequest()
	req.SafeTxHash = "0x" + strings.Repeat("5", 64)
	assertSigningBlockedFor(t, AuthorizeSigningRequest(proof, req), ReasonSigningRequestMismatch)
}

func TestAuthorizeSigningRequestBlocksInvalidSafeTxHash(t *testing.T) {
	proof, _ := Evaluate(validEnvelope())
	req := validSigningRequest()
	req.SafeTxHash = "not-a-hash"
	assertSigningBlockedFor(t, AuthorizeSigningRequest(proof, req), ReasonInvalidSigningRequest)
}

func TestAuthorizeSigningRequestDoesNotTrustTamperedSerializedAllow(t *testing.T) {
	proof, _ := Evaluate(validEnvelope())
	proof.Envelope.Payload.GeneratedCalldataSHA256 = strings.Repeat("5", 64)
	proof.Evaluation.Decision = DecisionAllow
	got := AuthorizeSigningRequest(proof, validSigningRequest())
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, expected BLOCK", got.Decision)
	}
}

func assertSigningBlockedFor(t *testing.T, got SigningGateResult, reason ReasonCode) {
	t.Helper()
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, expected BLOCK", got.Decision)
	}
	for _, r := range got.Reasons {
		if r == reason {
			return
		}
	}
	t.Fatalf("reason %s not found in %v", reason, got.Reasons)
}
