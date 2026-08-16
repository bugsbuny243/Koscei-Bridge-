package nodeshield

import (
	"context"
	"fmt"
)

// WorkloadIdentityVerifier independently verifies that the cgroup selected for
// kernel enforcement belongs to the reviewed workload/artifact represented by
// BPFLoadConfig. Merely writing an approved digest into a BPF map is not an
// identity proof and must never be treated as one.
type WorkloadIdentityVerifier interface {
	VerifyWorkloadIdentity(ctx context.Context, config BPFLoadConfig) error
}

// RequireVerifiedWorkloadIdentity centralizes the fail-closed boundary used by
// privileged backends before any enforcement gate is armed.
func RequireVerifiedWorkloadIdentity(ctx context.Context, verifier WorkloadIdentityVerifier, config BPFLoadConfig) error {
	if verifier == nil {
		return fmt.Errorf("workload identity verifier is required")
	}
	if err := verifier.VerifyWorkloadIdentity(ctx, config); err != nil {
		return fmt.Errorf("verify workload identity: %w", err)
	}
	return nil
}
