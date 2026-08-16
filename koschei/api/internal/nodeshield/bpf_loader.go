package nodeshield

import (
	"context"
	"fmt"
)

// BPFLoadResult is the minimum attested state required before Node Shield may
// expose kernel prevention. Backend-specific handles remain outside the common core.
type BPFLoadResult struct {
	ObjectsVerified   bool `json:"objects_verified"`
	LSMAttached       bool `json:"lsm_attached"`
	ConnectAttached   bool `json:"connect_attached"`
	PolicyMapsReady   bool `json:"policy_maps_ready"`
	ArtifactBound     bool `json:"artifact_bound"`
}

// BPFBackend owns privileged kernel operations. Implementations may use
// cilium/ebpf, libbpf bindings, or a narrow helper process, but they must return
// explicit attachment state rather than relying on successful construction.
type BPFBackend interface {
	LoadAndAttach(ctx context.Context, objects []BPFObjectManifest) (BPFLoadResult, error)
}

// LoadVerifiedBPF verifies immutable object digests before any privileged
// kernel loading occurs, then fail-closes unless all required enforcement state
// is confirmed by the backend.
func LoadVerifiedBPF(ctx context.Context, backend BPFBackend, objects []BPFObjectManifest) (BPFLoadResult, error) {
	if backend == nil {
		return BPFLoadResult{}, fmt.Errorf("BPF backend is required")
	}
	if err := VerifyBPFObjects(objects); err != nil {
		return BPFLoadResult{}, fmt.Errorf("verify BPF objects: %w", err)
	}

	result, err := backend.LoadAndAttach(ctx, objects)
	if err != nil {
		return BPFLoadResult{}, fmt.Errorf("load and attach BPF objects: %w", err)
	}
	result.ObjectsVerified = true
	if !result.LSMAttached || !result.ConnectAttached || !result.PolicyMapsReady || !result.ArtifactBound {
		return result, fmt.Errorf("BPF prevention state incomplete: lsm=%t connect=%t maps=%t artifact=%t",
			result.LSMAttached, result.ConnectAttached, result.PolicyMapsReady, result.ArtifactBound)
	}
	return result, nil
}
