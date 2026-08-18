package matrixcontainment

import (
	"context"
	"errors"
	"testing"
)

type stubRunner struct {
	observation Observation
	err         error
}

func (r stubRunner) Observe(context.Context, CellInput) (Observation, error) {
	return r.observation, r.err
}

func runnerFixtureInput() CellInput {
	return CellInput{
		ChainID:                 1,
		BlockNumber:             23456789,
		BlockHash:               "1111111111111111111111111111111111111111111111111111111111111111",
		Target:                  "0x1111111111111111111111111111111111111111",
		ApprovedIntentSHA256:    "2222222222222222222222222222222222222222222222222222222222222222",
		CandidateIntentSHA256:   "2222222222222222222222222222222222222222222222222222222222222222",
		ApprovedPayloadSHA256:   "3333333333333333333333333333333333333333333333333333333333333333",
		CandidatePayloadSHA256:  "3333333333333333333333333333333333333333333333333333333333333333",
		InvariantSetSHA256:      "4444444444444444444444444444444444444444444444444444444444444444",
		ApprovedRunnerSHA256:    "5555555555555555555555555555555555555555555555555555555555555555",
	}
}

func runnerFixtureObservation() Observation {
	return Observation{
		BackendAvailable:            true,
		ObservedChainID:             1,
		ObservedBlockNumber:         23456789,
		ObservedBlockHash:           "1111111111111111111111111111111111111111111111111111111111111111",
		ObservedRunnerSHA256:        "5555555555555555555555555555555555555555555555555555555555555555",
		PreStateSHA256:              "6666666666666666666666666666666666666666666666666666666666666666",
		PostStateSHA256:             "7777777777777777777777777777777777777777777777777777777777777777",
		EffectSetSHA256:             "8888888888888888888888888888888888888888888888888888888888888888",
		AuthorityPreserved:          true,
		AssetBoundsPreserved:        true,
		CodeIntegrityPreserved:      true,
		ExecutionPathFullyObserved:  true,
		InvariantsPass:              true,
	}
}

func TestEvaluateWithRunnerVerifiedObservationCanRelease(t *testing.T) {
	receipt, err := EvaluateWithRunner(context.Background(), runnerFixtureInput(), stubRunner{observation: runnerFixtureObservation()})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != DecisionRelease || !Verify(receipt) {
		t.Fatalf("decision=%s reasons=%v verify=%v", receipt.Decision, receipt.Reasons, Verify(receipt))
	}
}

func TestEvaluateWithRunnerNilRunnerIsUnavailable(t *testing.T) {
	receipt, err := EvaluateWithRunner(context.Background(), runnerFixtureInput(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != DecisionUnavailable {
		t.Fatalf("decision=%s, want UNAVAILABLE", receipt.Decision)
	}
}

func TestEvaluateWithRunnerFailureIsUnavailable(t *testing.T) {
	receipt, err := EvaluateWithRunner(context.Background(), runnerFixtureInput(), stubRunner{err: errors.New("isolated backend failed")})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != DecisionUnavailable {
		t.Fatalf("decision=%s, want UNAVAILABLE", receipt.Decision)
	}
}

func TestEvaluateWithRunnerCancelledContextIsUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	receipt, err := EvaluateWithRunner(ctx, runnerFixtureInput(), stubRunner{observation: runnerFixtureObservation()})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != DecisionUnavailable {
		t.Fatalf("decision=%s, want UNAVAILABLE", receipt.Decision)
	}
}
