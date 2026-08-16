package nodeshield

import (
	"context"
	"errors"
	"testing"
)

type fakeIdentityVerifier struct{ err error }

func (f fakeIdentityVerifier) VerifyWorkloadIdentity(_ context.Context, _ BPFLoadConfig) error { return f.err }

func TestRequireVerifiedWorkloadIdentityRejectsMissingVerifier(t *testing.T) {
	if err := RequireVerifiedWorkloadIdentity(context.Background(), nil, BPFLoadConfig{}); err == nil {
		t.Fatal("expected missing identity verifier to fail closed")
	}
}

func TestRequireVerifiedWorkloadIdentityRejectsFailedVerification(t *testing.T) {
	if err := RequireVerifiedWorkloadIdentity(context.Background(), fakeIdentityVerifier{err: errors.New("mismatch")}, BPFLoadConfig{}); err == nil {
		t.Fatal("expected failed identity verification to fail closed")
	}
}

func TestRequireVerifiedWorkloadIdentityAcceptsVerifiedWorkload(t *testing.T) {
	if err := RequireVerifiedWorkloadIdentity(context.Background(), fakeIdentityVerifier{}, BPFLoadConfig{}); err != nil {
		t.Fatalf("expected verified workload identity: %v", err)
	}
}
