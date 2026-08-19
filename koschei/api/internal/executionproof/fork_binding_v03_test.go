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

func (f fixedVerifiedForkBackend) ExecuteVerifiedFork(context.Context, PreparedVerifiedForkRequest) (VerifiedForkBackendResult, error) {
	return f.result, f.err
}

func validVerifiedForkRequest() VerifiedForkRequest {
	return VerifiedForkRequest{
		Version:            ExecutionProofForkBindingVersion,
		ChainID:            1,
		ReferenceBlock:     12345678,
		ReferenceBlockHash: "0x" + strings.Repeat("a", 64),
		Payload: EVMPayload{
			From:     "0x" + strings.Repeat("1", 40),
			To:       "0x" + strings.Repeat("2", 40),
			ValueHex: "0x0",
			DataHex:  "0x1234",
		},
		RunnerSHA256: strings.Repeat("d", 64),
		Invariants: []ApprovedInvariantDefinition{
			{ID: "supply-bound", Class: InvariantAssetConservation, ParametersSHA256: strings.Repeat("1", 64)},
			{ID: "proxy-codehash", Class: InvariantProxyCodehash, ParametersSHA256: strings.Repeat("2", 64)},
		},
	}
}

func validVerifiedForkBackendResult(t *testing.T, req VerifiedForkRequest) VerifiedForkBackendResult {
	t.Helper()
	prepared, ok := prepareVerifiedForkRequest(req)
	if !ok { t.Fatal("valid request did not prepare") }
	sim := prepared.Simulation
	return VerifiedForkBackendResult{
		ObservedRunnerSHA256: sim.RunnerSHA256,
		Simulation: ForkBackendResult{
			ChainID:                  sim.ChainID,
			ObservedReferenceBlock:   sim.ReferenceBlock,
			ObservedReferenceHash:    sim.ReferenceBlockHash,
			ObservedPayloadSHA256:    sim.PayloadSHA256,
			ObservedInvariantSetHash: sim.InvariantSetSHA256,
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
	if !ok { t.Fatal("prepare failed") }
	req.Invariants[0], req.Invariants[1] = req.Invariants[1], req.Invariants[0]
	second, ok := prepareVerifiedForkRequest(req)
	if !ok { t.Fatal("prepare failed after reorder") }
	if first.Simulation.InvariantSetSHA256 != second.Simulation.InvariantSetSHA256 {
		t.Fatalf("invariant digest depends on input order: %s != %s", first.Simulation.InvariantSetSHA256, second.Simulation.InvariantSetSHA256)
	}
	if first.Simulation.RequiredCheckIDs[0] != "proxy-codehash" || first.Simulation.RequiredCheckIDs[1] != "supply-bound" {
		t.Fatalf("required IDs not canonical: %#v", first.Simulation.RequiredCheckIDs)
	}
}

func TestVerifiedForkInvariantParameterMutationChangesIdentity(t *testing.T) {
	req := validVerifiedForkRequest()
	first, _ := prepareVerifiedForkRequest(req)
	req.Invariants[0].ParametersSHA256 = strings.Repeat("9", 64)
	second, _ := prepareVerifiedForkRequest(req)
	if first.Simulation.InvariantSetSHA256 == second.Simulation.InvariantSetSHA256 {
		t.Fatal("mutated invariant parameters did not change invariant-set identity")
	}
}

func TestVerifiedForkPayloadMutationChangesDerivedIdentity(t *testing.T) {
	req := validVerifiedForkRequest()
	first, ok := prepareVerifiedForkRequest(req)
	if !ok { t.Fatal("prepare failed") }
	req.Payload.DataHex = "0xabcd"
	second, ok := prepareVerifiedForkRequest(req)
	if !ok { t.Fatal("prepare failed after payload mutation") }
	if first.Simulation.PayloadSHA256 == second.Simulation.PayloadSHA256 {
		t.Fatal("mutated raw EVM payload did not change derived payload identity")
	}
}

func TestVerifiedForkCanonicalPayloadIsCarriedToBackend(t *testing.T) {
	req := validVerifiedForkRequest()
	req.Payload.From = "0x" + strings.ToUpper(strings.Repeat("a", 40))
	prepared, ok := prepareVerifiedForkRequest(req)
	if !ok { t.Fatal("prepare failed") }
	if prepared.Payload.From != "0x"+strings.Repeat("a", 40) {
		t.Fatalf("payload not canonicalized: %#v", prepared.Payload)
	}
}

func TestVerifiedForkRejectsMalformedRawPayload(t *testing.T) {
	req := validVerifiedForkRequest()
	req.Payload.DataHex = "0x123"
	if _, ok := prepareVerifiedForkRequest(req); ok { t.Fatal("odd-length EVM calldata accepted") }
}

func TestRunVerifiedForkAllowsMatchingObservedRunnerAndDefinitions(t *testing.T) {
	req := validVerifiedForkRequest()
	backend := fixedVerifiedForkBackend{result: validVerifiedForkBackendResult(t, req)}
	receipt, err := RunVerifiedForkInvariants(context.Background(), req, backend)
	if err != nil { t.Fatal(err) }
	if receipt.Decision != SimulationAllow { t.Fatalf("decision = %s reasons = %v", receipt.Decision, receipt.Reasons) }
}

func TestRunVerifiedForkBlocksObservedRunnerMismatch(t *testing.T) {
	req := validVerifiedForkRequest()
	result := validVerifiedForkBackendResult(t, req)
	result.ObservedRunnerSHA256 = strings.Repeat("8", 64)
	receipt, err := RunVerifiedForkInvariants(context.Background(), req, fixedVerifiedForkBackend{result: result})
	if !errors.Is(err, ErrSimulationBlocked) { t.Fatalf("error = %v, want ErrSimulationBlocked", err) }
	assertSimulationReceiptReason(t, receipt, SimulationRunnerMismatch)
}

func TestRunVerifiedForkBlocksObservedInvariantSetMismatch(t *testing.T) {
	req := validVerifiedForkRequest()
	result := validVerifiedForkBackendResult(t, req)
	result.Simulation.ObservedInvariantSetHash = strings.Repeat("7", 64)
	receipt, err := RunVerifiedForkInvariants(context.Background(), req, fixedVerifiedForkBackend{result: result})
	if !errors.Is(err, ErrSimulationBlocked) { t.Fatalf("error = %v, want ErrSimulationBlocked", err) }
	assertSimulationReceiptReason(t, receipt, SimulationInvariantDefinitionMismatch)
}

func TestVerifiedForkRejectsDuplicateInvariantDefinitions(t *testing.T) {
	req := validVerifiedForkRequest()
	req.Invariants[1].ID = req.Invariants[0].ID
	if _, ok := prepareVerifiedForkRequest(req); ok { t.Fatal("duplicate invariant definitions accepted") }
}

func TestRunVerifiedForkBlocksBackendFailure(t *testing.T) {
	req := validVerifiedForkRequest()
	receipt, err := RunVerifiedForkInvariants(context.Background(), req, fixedVerifiedForkBackend{err: errors.New("fork failed")})
	if err == nil { t.Fatal("expected backend error") }
	assertSimulationReceiptReason(t, receipt, SimulationBackendFailure)
}
