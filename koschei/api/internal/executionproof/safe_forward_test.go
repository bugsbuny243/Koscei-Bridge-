package executionproof

import (
	"context"
	"errors"
	"testing"
)

type recordingSafeForwarder struct {
	calls int
	err   error
}

func (f *recordingSafeForwarder) ForwardSafeTransaction(context.Context, SafeForwardRequest) error {
	f.calls++
	return f.err
}

func TestVerifyAndForwardSafeTransactionCallsForwarderOnlyAfterAllow(t *testing.T) {
	req := validSafeForwardRequest()
	computer := fixedSafeHashComputer{hash: req.PresentedSafeHash}
	proof := proofForSafeForward(t, req)
	forwarder := &recordingSafeForwarder{}

	got, err := VerifyAndForwardSafeTransaction(context.Background(), proof, req, computer, forwarder)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != DecisionAllow {
		t.Fatalf("decision = %s, reasons = %v", got.Decision, got.Reasons)
	}
	if forwarder.calls != 1 {
		t.Fatalf("forward calls = %d, want 1", forwarder.calls)
	}
}

func TestVerifyAndForwardSafeTransactionNeverForwardsBlockedRequest(t *testing.T) {
	req := validSafeForwardRequest()
	proof := proofForSafeForward(t, req)
	forwarder := &recordingSafeForwarder{}

	req.Transaction.Operation = 2
	got, err := VerifyAndForwardSafeTransaction(context.Background(), proof, req, fixedSafeHashComputer{hash: req.PresentedSafeHash}, forwarder)
	if !errors.Is(err, ErrSigningBlocked) {
		t.Fatalf("error = %v, want ErrSigningBlocked", err)
	}
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK", got.Decision)
	}
	if forwarder.calls != 0 {
		t.Fatalf("blocked request reached forwarder: calls=%d", forwarder.calls)
	}
}

func TestVerifyAndForwardSafeTransactionDoesNotForwardOnHashMismatch(t *testing.T) {
	req := validSafeForwardRequest()
	proof := proofForSafeForward(t, req)
	forwarder := &recordingSafeForwarder{}

	got, err := VerifyAndForwardSafeTransaction(context.Background(), proof, req, fixedSafeHashComputer{hash: "0x5555555555555555555555555555555555555555555555555555555555555555"}, forwarder)
	if !errors.Is(err, ErrSigningBlocked) {
		t.Fatalf("error = %v, want ErrSigningBlocked", err)
	}
	assertSigningBlockedFor(t, got, ReasonSafeHashMismatch)
	if forwarder.calls != 0 {
		t.Fatalf("hash mismatch reached forwarder: calls=%d", forwarder.calls)
	}
}

func TestVerifyAndForwardSafeTransactionPropagatesForwarderFailure(t *testing.T) {
	req := validSafeForwardRequest()
	proof := proofForSafeForward(t, req)
	forwardErr := errors.New("safe transport unavailable")
	forwarder := &recordingSafeForwarder{err: forwardErr}

	got, err := VerifyAndForwardSafeTransaction(context.Background(), proof, req, fixedSafeHashComputer{hash: req.PresentedSafeHash}, forwarder)
	if !errors.Is(err, forwardErr) {
		t.Fatalf("error = %v, want %v", err, forwardErr)
	}
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK on forward failure", got.Decision)
	}
	if forwarder.calls != 1 {
		t.Fatalf("forward calls = %d, want 1", forwarder.calls)
	}
}
