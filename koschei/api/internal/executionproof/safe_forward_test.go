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

func nativeSafeForwardFixture(t *testing.T) (SafeForwardRequest, Proof) {
	t.Helper()
	req := validSafeForwardRequest()
	hash, err := (NativeSafeTxHashComputer{}).ComputeSafeTxHash(req.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	req.PresentedSafeHash = hash
	return req, proofForSafeForward(t, req)
}

func TestVerifyAndForwardSafeTransactionCallsForwarderOnlyAfterAllow(t *testing.T) {
	req, proof := nativeSafeForwardFixture(t)
	forwarder := &recordingSafeForwarder{}

	got, err := VerifyAndForwardSafeTransaction(context.Background(), proof, req, forwarder)
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
	req, proof := nativeSafeForwardFixture(t)
	forwarder := &recordingSafeForwarder{}

	req.Transaction.Operation = 2
	got, err := VerifyAndForwardSafeTransaction(context.Background(), proof, req, forwarder)
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
	req, proof := nativeSafeForwardFixture(t)
	forwarder := &recordingSafeForwarder{}

	req.PresentedSafeHash = "0x5555555555555555555555555555555555555555555555555555555555555555"
	got, err := VerifyAndForwardSafeTransaction(context.Background(), proof, req, forwarder)
	if !errors.Is(err, ErrSigningBlocked) {
		t.Fatalf("error = %v, want ErrSigningBlocked", err)
	}
	assertSigningBlockedFor(t, got, ReasonSafeHashMismatch)
	if forwarder.calls != 0 {
		t.Fatalf("hash mismatch reached forwarder: calls=%d", forwarder.calls)
	}
}

func TestVerifyAndForwardSafeTransactionPropagatesForwarderFailure(t *testing.T) {
	req, proof := nativeSafeForwardFixture(t)
	forwardErr := errors.New("safe transport unavailable")
	forwarder := &recordingSafeForwarder{err: forwardErr}

	got, err := VerifyAndForwardSafeTransaction(context.Background(), proof, req, forwarder)
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

func TestVerifyAndForwardSafeTransactionBlocksCancelledContextBeforeForward(t *testing.T) {
	req, proof := nativeSafeForwardFixture(t)
	forwarder := &recordingSafeForwarder{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := VerifyAndForwardSafeTransaction(ctx, proof, req, forwarder)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK", got.Decision)
	}
	if forwarder.calls != 0 {
		t.Fatalf("cancelled request reached forwarder: calls=%d", forwarder.calls)
	}
}
