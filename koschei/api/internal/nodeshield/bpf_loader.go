package nodeshield

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// BPFEndpoint4 is one exact IPv4 endpoint authorized for a protected workload.
type BPFEndpoint4 struct {
	Address netip.Addr `json:"address"`
	Port    uint16     `json:"port"`
}

// BPFLoadConfig binds privileged kernel state to one reviewed workload.
// CgroupID must identify the same cgroup v2 directory supplied in CgroupPath.
type BPFLoadConfig struct {
	WorkloadID     string         `json:"workload_id"`
	CgroupPath     string         `json:"cgroup_path"`
	CgroupID       uint64         `json:"cgroup_id"`
	ArtifactSHA256 string         `json:"artifact_sha256"`
	DenyExec       bool           `json:"deny_exec"`
	DenyFileWrite  bool           `json:"deny_file_write"`
	DenyPrivilege  bool           `json:"deny_privilege"`
	AllowedIPv4    []BPFEndpoint4 `json:"allowed_ipv4,omitempty"`
}

func (c BPFLoadConfig) Validate() error {
	if strings.TrimSpace(c.WorkloadID) == "" {
		return fmt.Errorf("workload id is required")
	}
	if strings.TrimSpace(c.CgroupPath) == "" || c.CgroupID == 0 {
		return fmt.Errorf("cgroup path and id are required")
	}
	if len(strings.TrimSpace(c.ArtifactSHA256)) != 64 {
		return fmt.Errorf("artifact sha256 must be 64 hexadecimal characters")
	}
	for _, endpoint := range c.AllowedIPv4 {
		if !endpoint.Address.Is4() || endpoint.Port == 0 {
			return fmt.Errorf("invalid IPv4 endpoint %s:%d", endpoint.Address, endpoint.Port)
		}
	}
	return nil
}

// BPFLoadResult is the minimum attested state required before Node Shield may
// expose kernel prevention. Backend-specific handles remain outside the common core.
type BPFLoadResult struct {
	ObjectsVerified bool `json:"objects_verified"`
	LSMAttached     bool `json:"lsm_attached"`
	ConnectAttached bool `json:"connect_attached"`
	PolicyMapsReady bool `json:"policy_maps_ready"`
	ArtifactBound   bool `json:"artifact_bound"`
}

// BPFBackend owns privileged kernel operations. Implementations must keep
// attachment handles alive for the protected workload until explicitly closed.
type BPFBackend interface {
	LoadAndAttach(ctx context.Context, config BPFLoadConfig, objects []BPFObjectManifest) (BPFLoadResult, error)
}

// LoadVerifiedBPF verifies immutable object digests before any privileged
// kernel loading occurs, then fail-closes unless all required enforcement state
// is confirmed by the backend.
func LoadVerifiedBPF(ctx context.Context, backend BPFBackend, config BPFLoadConfig, objects []BPFObjectManifest) (BPFLoadResult, error) {
	if backend == nil {
		return BPFLoadResult{}, fmt.Errorf("BPF backend is required")
	}
	if err := config.Validate(); err != nil {
		return BPFLoadResult{}, fmt.Errorf("validate BPF load config: %w", err)
	}
	if err := VerifyBPFObjects(objects); err != nil {
		return BPFLoadResult{}, fmt.Errorf("verify BPF objects: %w", err)
	}

	result, err := backend.LoadAndAttach(ctx, config, objects)
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
