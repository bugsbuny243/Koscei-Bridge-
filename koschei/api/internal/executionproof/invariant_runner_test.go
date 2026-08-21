package executionproof

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fixedForkBackend struct {
	result ForkBackendResult
	err    error
}

func (f fixedForkBackend) ExecuteForkSimulation(context.Context, ForkSimulationRequest) (ForkBackendResult, error) {
	return f.result, f.err
}

func validForkRequest() ForkSimulationRequest {
	return ForkSimulationRequest{
		Version:            InvariantRunnerVersion,
		ChainID:            1,
		ReferenceBlock:     12345678,
		ReferenceBlockHash: "0x" + strings.Repeat("a", 64),
		PayloadSHA256:      strings.Repeat("b", 64),
		InvariantSetSHA256: strings.Repeat("c", 64),
		RunnerSHA256:       strings.Repeat("d", 64),
		RequiredCheckIDs:   []string{"supply-bound", "proxy-codehash"},
	}
}

func validForkBackendResult(req ForkSimulationRequest) ForkBackendResult {
	return ForkBackendResult{
		ChainID:                  req.ChainID,
		ObservedReferenceBlock:   req.ReferenceBlock,
		ObservedReferenceHash:    req.ReferenceBlockHash,
		ObservedPayloadSHA256:    req.PayloadSHA256,
		ObservedInvariantSetHash: req.InvariantSetSHA256,
		Checks: []InvariantCheck{
			{ID: "proxy-codehash", Class: InvariantProxyCodehash, Passed: true, Evidence: strings.Repeat("e", 64)},
			{ID: "supply-bound", Class: InvariantAssetConservation, Passed: true, Evidence: strings.Repeat("f", 64)},
		},
	}
}

func TestRunForkInvariantsAllowsPinnedMatchingEvidence(t *testing.T) {
	req := validForkRequest()
	receipt, err := RunForkInvariants(context.Background(), req, fixedForkBackend{result: validForkBackendResult(req)})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != SimulationAllow {
		t.Fatalf("decision = %s, reasons = %v", receipt.Decision, receipt.Reasons)
	}
	if !validSHA256(receipt.ReceiptSHA256) {
		t.Fatalf("invalid receipt digest %q", receipt.ReceiptSHA256)
	}
	if len(receipt.Checks) != 2 || receipt.Checks[0].ID != "proxy-codehash" || receipt.Checks[1].ID != "supply-bound" {
		t.Fatalf("checks not canonicalized: %#v", receipt.Checks)
	}
	if len(receipt.RequiredCheckIDs) != 2 || receipt.RequiredCheckIDs[0] != "proxy-codehash" || receipt.RequiredCheckIDs[1] != "supply-bound" {
		t.Fatalf("required checks not canonicalized: %#v", receipt.RequiredCheckIDs)
	}
}

func TestRunForkInvariantsIsDeterministicAcrossBackendCheckOrder(t *testing.T) {
	req := validForkRequest()
	firstResult := validForkBackendResult(req)
	secondResult := validForkBackendResult(req)
	secondResult.Checks[0], secondResult.Checks[1] = secondResult.Checks[1], secondResult.Checks[0]
	first, err := RunForkInvariants(context.Background(), req, fixedForkBackend{result: firstResult})
	if err != nil {
		t.Fatal(err)
	}
	second, err := RunForkInvariants(context.Background(), req, fixedForkBackend{result: secondResult})
	if err != nil {
		t.Fatal(err)
	}
	if first.ReceiptSHA256 != second.ReceiptSHA256 {
		t.Fatalf("receipt digest depends on backend check order: %s != %s", first.ReceiptSHA256, second.ReceiptSHA256)
	}
}

func TestRunForkInvariantsNormalizesIDsBeforeCanonicalSort(t *testing.T) {
	req := validForkRequest()
	req.RequiredCheckIDs = []string{" supply-bound ", " proxy-codehash "}
	firstResult := validForkBackendResult(req)
	secondResult := validForkBackendResult(req)
	secondResult.Checks[0].ID = "  proxy-codehash  "
	first, err := RunForkInvariants(context.Background(), req, fixedForkBackend{result: firstResult})
	if err != nil {
		t.Fatal(err)
	}
	second, err := RunForkInvariants(context.Background(), req, fixedForkBackend{result: secondResult})
	if err != nil {
		t.Fatal(err)
	}
	if first.ReceiptSHA256 != second.ReceiptSHA256 {
		t.Fatalf("receipt digest depends on surrounding invariant ID whitespace: %s != %s", first.ReceiptSHA256, second.ReceiptSHA256)
	}
}

func TestRunForkInvariantsBlocksMissingRequiredInvariant(t *testing.T) {
	req := validForkRequest()
	result := validForkBackendResult(req)
	result.Checks = result.Checks[:1]
	assertSimulationBlockedFor(t, req, result, SimulationCheckSetMismatch)
}

func TestRunForkInvariantsBlocksUnexpectedInvariant(t *testing.T) {
	req := validForkRequest()
	result := validForkBackendResult(req)
	result.Checks = append(result.Checks, InvariantCheck{ID: "unexpected", Class: InvariantTreasuryBound, Passed: true, Evidence: strings.Repeat("1", 64)})
	assertSimulationBlockedFor(t, req, result, SimulationCheckSetMismatch)
}

func TestRunForkInvariantsRejectsEmptyRequiredInvariantSet(t *testing.T) {
	req := validForkRequest()
	req.RequiredCheckIDs = nil
	receipt, err := RunForkInvariants(context.Background(), req, fixedForkBackend{result: validForkBackendResult(req)})
	if !errors.Is(err, ErrSimulationBlocked) {
		t.Fatalf("error = %v, want ErrSimulationBlocked", err)
	}
	assertSimulationReceiptReason(t, receipt, SimulationInvalidRequest)
}

func TestRunForkInvariantsRejectsDuplicateRequiredInvariantIDs(t *testing.T) {
	req := validForkRequest()
	req.RequiredCheckIDs = []string{"proxy-codehash", " proxy-codehash "}
	receipt, err := RunForkInvariants(context.Background(), req, fixedForkBackend{result: validForkBackendResult(req)})
	if !errors.Is(err, ErrSimulationBlocked) {
		t.Fatalf("error = %v, want ErrSimulationBlocked", err)
	}
	assertSimulationReceiptReason(t, receipt, SimulationInvalidRequest)
}

func TestRunForkInvariantsBlocksReferenceStateMismatch(t *testing.T) {
	req := validForkRequest()
	result := validForkBackendResult(req)
	result.ObservedReferenceHash = "0x" + strings.Repeat("1", 64)
	assertSimulationBlockedFor(t, req, result, SimulationStateMismatch)
}
func TestRunForkInvariantsBlocksPayloadMismatch(t *testing.T) {
	req := validForkRequest()
	result := validForkBackendResult(req)
	result.ObservedPayloadSHA256 = strings.Repeat("1", 64)
	assertSimulationBlockedFor(t, req, result, SimulationPayloadMismatch)
}
func TestRunForkInvariantsBlocksInvariantSetMismatch(t *testing.T) {
	req := validForkRequest()
	result := validForkBackendResult(req)
	result.ObservedInvariantSetHash = strings.Repeat("1", 64)
	assertSimulationBlockedFor(t, req, result, SimulationInvariantDrift)
}
func TestRunForkInvariantsBlocksFailedInvariant(t *testing.T) {
	req := validForkRequest()
	result := validForkBackendResult(req)
	result.Checks[0].Passed = false
	assertSimulationBlockedFor(t, req, result, SimulationInvariantFailure)
}
func TestRunForkInvariantsBlocksMissingChecks(t *testing.T) {
	req := validForkRequest()
	result := validForkBackendResult(req)
	result.Checks = nil
	assertSimulationBlockedFor(t, req, result, SimulationMissingChecks)
}
func TestRunForkInvariantsBlocksDuplicateCheckIDs(t *testing.T) {
	req := validForkRequest()
	result := validForkBackendResult(req)
	result.Checks[1].ID = result.Checks[0].ID
	assertSimulationBlockedFor(t, req, result, SimulationDuplicateCheck)
}
func TestRunForkInvariantsBlocksMalformedEvidence(t *testing.T) {
	req := validForkRequest()
	result := validForkBackendResult(req)
	result.Checks[0].Evidence = "not-a-digest"
	assertSimulationBlockedFor(t, req, result, SimulationInvalidEvidence)
}
func TestRunForkInvariantsBlocksBackendFailure(t *testing.T) {
	req := validForkRequest()
	receipt, err := RunForkInvariants(context.Background(), req, fixedForkBackend{err: errors.New("fork unavailable")})
	if err == nil {
		t.Fatal("expected backend error")
	}
	assertSimulationReceiptReason(t, receipt, SimulationBackendFailure)
}
func TestRunForkInvariantsBlocksCancelledContextBeforeBackend(t *testing.T) {
	req := validForkRequest()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	receipt, err := RunForkInvariants(ctx, req, fixedForkBackend{result: validForkBackendResult(req)})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	assertSimulationReceiptReason(t, receipt, SimulationBackendFailure)
}
func TestRunForkInvariantsRejectsInvalidRequest(t *testing.T) {
	req := validForkRequest()
	req.ReferenceBlockHash = "bad"
	receipt, err := RunForkInvariants(context.Background(), req, fixedForkBackend{})
	if !errors.Is(err, ErrSimulationBlocked) {
		t.Fatalf("error = %v, want ErrSimulationBlocked", err)
	}
	assertSimulationReceiptReason(t, receipt, SimulationInvalidRequest)
}

func assertSimulationBlockedFor(t *testing.T, req ForkSimulationRequest, result ForkBackendResult, reason SimulationReason) {
	t.Helper()
	receipt, err := RunForkInvariants(context.Background(), req, fixedForkBackend{result: result})
	if !errors.Is(err, ErrSimulationBlocked) {
		t.Fatalf("error = %v, want ErrSimulationBlocked", err)
	}
	assertSimulationReceiptReason(t, receipt, reason)
}
func assertSimulationReceiptReason(t *testing.T, receipt ForkSimulationReceipt, reason SimulationReason) {
	t.Helper()
	if receipt.Decision != SimulationBlock {
		t.Fatalf("decision = %s, want BLOCK", receipt.Decision)
	}
	for _, got := range receipt.Reasons {
		if got == reason {
			return
		}
	}
	t.Fatalf("reason %s not present in %v", reason, receipt.Reasons)
}
