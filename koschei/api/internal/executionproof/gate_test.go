package executionproof

import (
	"strings"
	"testing"
)

func TestAuthorizeForSigningAllowsRecomputedValidProof(t *testing.T) {
	proof, err := Evaluate(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	got := AuthorizeForSigning(proof)
	if got.Decision != DecisionAllow {
		t.Fatalf("decision = %s, reasons = %v", got.Decision, got.Reasons)
	}
}

func TestAuthorizeForSigningIgnoresTamperedSerializedAllow(t *testing.T) {
	e := validEnvelope()
	e.Payload.GeneratedCalldataSHA256 = strings.Repeat("4", 64)
	proof, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	proof.Evaluation = Evaluation{Decision: DecisionAllow}

	got := AuthorizeForSigning(proof)
	if got.Decision != DecisionBlock {
		t.Fatalf("tampered ALLOW was trusted: %+v", got)
	}
	assertReason(t, got, ReasonPayloadMismatch)
}

func TestAuthorizeForSigningBlocksTamperedEnvelopeHash(t *testing.T) {
	proof, err := Evaluate(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	proof.EnvelopeSHA256 = strings.Repeat("0", 64)

	got := AuthorizeForSigning(proof)
	if got.Decision != DecisionBlock {
		t.Fatalf("tampered hash was accepted: %+v", got)
	}
	assertReason(t, got, ReasonProofHashMismatch)
}

func assertReason(t *testing.T, evaluation Evaluation, reason ReasonCode) {
	t.Helper()
	for _, got := range evaluation.Reasons {
		if got == reason {
			return
		}
	}
	t.Fatalf("reason %s not found in %v", reason, evaluation.Reasons)
}
