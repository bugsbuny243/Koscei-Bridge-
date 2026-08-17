package executionproof

import (
	"strings"
	"testing"
)

func TestAuthorizeForSigningAllowsRecomputedMatchingProof(t *testing.T) {
	proof, err := Evaluate(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	got := AuthorizeForSigning(proof)
	if got.Decision != DecisionAllow {
		t.Fatalf("decision = %s, reasons = %v", got.Decision, got.Reasons)
	}
}

func TestAuthorizeForSigningBlocksTamperedSerializedDecision(t *testing.T) {
	proof, _ := Evaluate(validEnvelope())
	proof.Envelope.Payload.GeneratedCalldataSHA256 = strings.Repeat("5", 64)
	proof.Evaluation.Decision = DecisionAllow
	got := AuthorizeForSigning(proof)
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, expected BLOCK", got.Decision)
	}
}

func TestAuthorizeForSigningBlocksTamperedEnvelopeHash(t *testing.T) {
	proof, _ := Evaluate(validEnvelope())
	proof.EnvelopeSHA256 = strings.Repeat("0", 64)
	got := AuthorizeForSigning(proof)
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, expected BLOCK", got.Decision)
	}
	found := false
	for _, reason := range got.Reasons {
		if reason == ReasonProofHashMismatch {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing %s in %v", ReasonProofHashMismatch, got.Reasons)
	}
}

func TestAuthorizeForSigningBlocksSigningRequestIdentityTamper(t *testing.T) {
	proof, _ := Evaluate(validEnvelope())
	proof.Envelope.Authorization.ApprovedSigningRequestID = "0x" + strings.Repeat("5", 64)
	proof.Evaluation.Decision = DecisionAllow
	got := AuthorizeForSigning(proof)
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, expected BLOCK", got.Decision)
	}
}
