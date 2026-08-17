package executionproof

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fixedVerifiedForkBackend struct {
	result VerifiedForkBackendResult
	err    error
}

func (f fixedVerifiedForkBackend) ExecuteVerifiedFork(context.Context, ForkSimulationRequest) (VerifiedForkBackendResult, error) {
	return f.result, f.err
}

func validVerifiedForkRequest() VerifiedForkRequest {
	return VerifiedForkRequest{
		Version:            ExecutionProofForkBindingVersion,
		ChainID:            1,
		ReferenceBlock:     12345678,
		ReferenceBlockHash: "0x" + strings.Repeat("a", 64),
		PayloadSHA256:      strings.Repeat("b", 64),
		RunnerSHA256:       strings.Repeat("d", 64),
		Invariants: []ApprovedInvariantDefinition{
			{ID: "supply-bound", Class: InvariantAssetConservation, ParametersSHA256: strings.Repeat("1", 64)},
			{ID: "proxy-codehash", Class: InvariantProxyCodehash, ParametersSHA256: strings.Repeat("2", 64)},
		},
	}
}

func validVerifiedForkBackendResult(t *testing.T, req VerifiedForkRequest) VerifiedForkBackendResult {
	t.Helper()
	prepared, ok := prepareVerifiedForkRequest(req)
	if !ok {
		t.Fatal("valid request did not prepare")
	}
	return VerifiedForkBackendResult{
		ObservedRunnerSHA256: prepared.RunnerSHA256,
		Simulation: ForkBackendResult{
			ChainID:                  prepared.ChainID,
			ObservedReferenceBlock:   prepared.ReferenceBlock,
			ObservedReferenceHash:    prepared.ReferenceBlockHash,
			ObservedPayloadSHA256:    prepared.PayloadSHA256,
			ObservedInvariantSetHash: prepared.InvariantSetSHA256,
			Checks: []InvariantCheck{
				{ID: "proxy-codehash", Class: InvariantProxyCodehash, Passed: true, Evidence: strings.Repeat("e", 64)},
				{ID: "supply-bound", Class: InvariantAssetConservation, Passed: true, Evidence: strings.Repeat("f", 64)},
			},
		},
	}
}

func TestVerifiedForkDerivesInvariantSetIdentity(t *testing.T) {
	req := validVerifiedForkRequest()
	first, ok := prepareVerifiedForkRequest(req)
	if !ok {
		t.Fatal("prepare failed")
	}
	req.Invariants[0], req.Invariants[1] = req.Invariants[1], req.Invariants[0]
	second, ok := prepareVerifiedForkRequest(req)
	if !ok {
		t.Fatal("prepare failed after reorder")
	}
	if first.InvariantSetSHA256 != second.InvariantSetSHA256 {
		t.Fatalf("invariant digest depends on input order: %s != %s", first.InvariantSetSHA256, second.InvariantSetSHA256)
	}
	if first.RequiredCheckIDs[0] != "proxy-codehash" || first.RequiredCheckIDs[1] != "supply-bound" {
		t.Fatalf("required IDs not canonical: %#v", first.RequiredCheckIDs)
	}
}

func TestVerifiedForkInvariantParameterMutationChangesIdentity(t *testing.T) {
	req := validVerifiedForkRequest()
	first, _ := prepareVerifiedForkRequest(req)
	req.Invariants[0].ParametersSHA256 = strings.Repeat("9", 64)
	second, _ := prepareVerifiedForkRequest(req)
	if first.InvariantSetSHA256 == second.InvariantSetSHA256 {
		t.Fatal("mutated invariant parameters did not change invariant-set identity")
	}
}

func TestRunVerifiedForkAllowsMatchingObservedRunnerAndDefinitions(t *testing.T) {
	req := validVerifiedForkRequest()
	backend := fixedVerifiedForkBackend{result: validVerifiedForkBackendResult(t, req)}
	receipt, err := RunVerifiedForkInvariants(context.Background(), req, backend)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != SimulationAllow {
		t.Fatalf("decision = %s reasons = %v", receipt.Decision, receipt.Reasons)
	}
}

func TestRunVerifiedForkBlocksObservedRunnerMismatch(t *testing.T) {
	req := validVerifiedForkRequest()
	result := validVerifiedForkBackendResult(t, req)
	result.ObservedRunnerSHA256 = strings.Repeat("8", 64)
	receipt, err := RunVerifiedForkInvariants(context.Background(), req, fixedVerifiedForkBackend{result: result})
	if !errors.Is(err, ErrSimulationBlocked) {
		t.Fatalf("error = %v, want ErrSimulationBlocked", err)
	}
	assertSimulationReceiptReason(t, receipt, SimulationRunnerMismatch)
}

func TestRunVerifiedForkBlocksObservedInvariantSetMismatch(t *testing.T) {
	req := validVerifiedForkRequest()
	result := validVerifiedForkBackendResult(t, req)
	result.Simulation.ObservedInvariantSetHash = strings.Repeat("7", 64)
	receipt, err := RunVerifiedForkInvariants(context.Background(), req, fixedVerifiedForkBackend{result: result})
	if !errors.Is(err, ErrSimulationBlocked) {
		t.Fatalf("error = %v, want ErrSimulationBlocked", err)
	}
	assertSimulationReceiptReason(t, receipt, SimulationInvariantDefinitionMismatch)
}

func TestVerifiedForkRejectsDuplicateInvariantDefinitions(t *testing.T) {
	req := validVerifiedForkRequest()
	req.Invariants[1].ID = req.Invariants[0].ID
	if _, ok := prepareVerifiedForkRequest(req); ok {
		t.Fatal("duplicate invariant definitions accepted")
	}
}

func TestRunVerifiedForkBlocksBackendFailure(t *testing.T) {
	req := validVerifiedForkRequest()
	receipt, err := RunVerifiedForkInvariants(context.Background(), req, fixedVerifiedForkBackend{err: errors.New("fork failed")})
	if err == nil {
		t.Fatal("expected backend error")
	}
	assertSimulationReceiptReason(t, receipt, SimulationBackendFailure)
}
