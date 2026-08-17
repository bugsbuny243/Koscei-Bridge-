package executionproof

import (
	"bytes"
	"strings"
	"testing"
)

func digest(ch byte) string { return strings.Repeat(string(ch), 64) }
func gitID(ch byte) string  { return strings.Repeat(string(ch), 40) }

func validEnvelope() Envelope {
	return Envelope{
		Version: Version,
		Source: SourceEvidence{
			CommitID: gitID('a'),
			TreeID:   gitID('b'),
		},
		Build: BuildEvidence{
			ToolchainSHA256:        digest('c'),
			ApprovedArtifactSHA256: digest('d'),
			BuiltArtifactSHA256:    digest('d'),
		},
		Runtime: RuntimeEvidence{
			ObservedArtifactSHA256: digest('d'),
			PolicySHA256:           digest('e'),
		},
		Payload: PayloadEvidence{
			ChainID:                 1,
			Target:                  "0x1111111111111111111111111111111111111111",
			ApprovedCalldataSHA256:  digest('f'),
			GeneratedCalldataSHA256: digest('f'),
			GeneratorSHA256:         strings.Repeat("1", 64),
		},
		Simulation: SimulationEvidence{
			InvariantSetSHA256: strings.Repeat("2", 64),
			Result:             "PASS",
		},
		Authorization: AuthorizationEvidence{
			SigningPolicySHA256: strings.Repeat("3", 64),
		},
	}
}

func TestEvaluateAllowsOnlyCompleteMatchingEvidence(t *testing.T) {
	proof, err := Evaluate(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if proof.Evaluation.Decision != DecisionAllow {
		t.Fatalf("decision = %s, reasons = %v", proof.Evaluation.Decision, proof.Evaluation.Reasons)
	}
	if len(proof.Evaluation.Reasons) != 0 {
		t.Fatalf("unexpected reasons: %v", proof.Evaluation.Reasons)
	}
	if !validSHA256(proof.EnvelopeSHA256) {
		t.Fatalf("invalid envelope hash: %q", proof.EnvelopeSHA256)
	}
}

func TestEvaluateBlocksArtifactMismatch(t *testing.T) {
	e := validEnvelope()
	e.Build.BuiltArtifactSHA256 = strings.Repeat("4", 64)
	proof, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedFor(t, proof, ReasonArtifactMismatch)
}

func TestEvaluateBlocksRuntimeArtifactMismatch(t *testing.T) {
	e := validEnvelope()
	e.Runtime.ObservedArtifactSHA256 = strings.Repeat("4", 64)
	proof, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedFor(t, proof, ReasonRuntimeArtifactMismatch)
}

func TestEvaluateBlocksPayloadMismatch(t *testing.T) {
	e := validEnvelope()
	e.Payload.GeneratedCalldataSHA256 = strings.Repeat("4", 64)
	proof, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedFor(t, proof, ReasonPayloadMismatch)
}

func TestEvaluateBlocksInvariantFailure(t *testing.T) {
	e := validEnvelope()
	e.Simulation.Result = "FAIL"
	proof, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedFor(t, proof, ReasonInvariantFailed)
}

func TestEvaluateRejectsMalformedSHA256Evidence(t *testing.T) {
	e := validEnvelope()
	e.Runtime.PolicySHA256 = strings.Repeat("z", 64)
	proof, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedFor(t, proof, ReasonInvalidEvidence)
}

func TestEvaluateAcceptsGitSHA1ObjectIDs(t *testing.T) {
	proof, err := Evaluate(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if proof.Evaluation.Decision != DecisionAllow {
		t.Fatalf("git sha1 object IDs rejected: %v", proof.Evaluation.Reasons)
	}
}

func TestEvaluateRejectsMalformedGitObjectID(t *testing.T) {
	e := validEnvelope()
	e.Source.CommitID = strings.Repeat("z", 40)
	proof, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedFor(t, proof, ReasonInvalidEvidence)
}

func TestCanonicalBytesAreDeterministic(t *testing.T) {
	first, err := Evaluate(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Evaluate(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := CanonicalBytes(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := CanonicalBytes(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("canonical bytes differ:\n%s\n%s", firstBytes, secondBytes)
	}
	if first.EnvelopeSHA256 != second.EnvelopeSHA256 {
		t.Fatalf("envelope hashes differ: %s != %s", first.EnvelopeSHA256, second.EnvelopeSHA256)
	}
}

func TestEvaluateDefaultsVersionButStillFailsClosedOnMissingEvidence(t *testing.T) {
	proof, err := Evaluate(Envelope{})
	if err != nil {
		t.Fatal(err)
	}
	if proof.Envelope.Version != Version {
		t.Fatalf("version = %q", proof.Envelope.Version)
	}
	assertBlockedFor(t, proof, ReasonInvalidEvidence)
}

func assertBlockedFor(t *testing.T, proof Proof, reason ReasonCode) {
	t.Helper()
	if proof.Evaluation.Decision != DecisionBlock {
		t.Fatalf("decision = %s, expected BLOCK", proof.Evaluation.Decision)
	}
	for _, got := range proof.Evaluation.Reasons {
		if got == reason {
			return
		}
	}
	t.Fatalf("reason %s not found in %v", reason, proof.Evaluation.Reasons)
}
