package nodeshield

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// BPFEndpoint is one exact IP endpoint authorized for a protected workload.
type BPFEndpoint struct {
	Address netip.Addr `json:"address"`
	Port    uint16     `json:"port"`
}

// BPFLoadConfig binds privileged kernel state to one reviewed workload.
// CgroupID must identify the same cgroup v2 directory supplied in CgroupPath.
type BPFLoadConfig struct {
	WorkloadID     string        `json:"workload_id"`
	CgroupPath     string        `json:"cgroup_path"`
	CgroupID       uint64        `json:"cgroup_id"`
	ArtifactSHA256 string        `json:"artifact_sha256"`
	DenyExec       bool          `json:"deny_exec"`
	DenyFileWrite  bool          `json:"deny_file_write"`
	DenyPrivilege  bool          `json:"deny_privilege"`
	AllowedIPs     []BPFEndpoint `json:"allowed_ips,omitempty"`
}

func (c BPFLoadConfig) Validate() error {
	if strings.TrimSpace(c.WorkloadID) == "" {
		return fmt.Errorf("workload id is required")
	}
	if strings.TrimSpace(c.CgroupPath) == "" || c.CgroupID == 0 {
		return fmt.Errorf("cgroup path and id are required")
	}
	if !isSHA256Hex(c.ArtifactSHA256) {
		return fmt.Errorf("artifact sha256 must be 64 hexadecimal characters")
	}
	for _, endpoint := range c.AllowedIPs {
		if !endpoint.Address.IsValid() || (!endpoint.Address.Is4() && !endpoint.Address.Is6()) || endpoint.Port == 0 {
			return fmt.Errorf("invalid IP endpoint %s:%d", endpoint.Address, endpoint.Port)
		}
	}
	return nil
}

// BPFLoadResult is the minimum attested state required before Node Shield may
// expose kernel prevention. Backend-specific handles remain outside the common core.
type BPFLoadResult struct {
	ObjectsVerified    bool `json:"objects_verified"`
	LSMAttached        bool `json:"lsm_attached"`
	ConnectAttached    bool `json:"connect_attached"`
	PolicyMapsReady    bool `json:"policy_maps_ready"`
	ArtifactBound      bool `json:"artifact_bound"`
	SubtreeScoped      bool `json:"subtree_scoped"`
	DualStack          bool `json:"dual_stack"`
	FileIOCovered      bool `json:"file_io_covered"`
	CredentialCovered  bool `json:"credential_covered"`
	RawSocketCovered   bool `json:"raw_socket_covered"`
	FrozenDuringArm    bool `json:"frozen_during_arm"`
	AtomicCgroupHandle bool `json:"atomic_cgroup_handle"`
}

// BPFBackend owns privileged kernel operations. Implementations must keep
// attachment handles alive for the protected workload until explicitly closed.
type BPFBackend interface {
	LoadAndAttach(ctx context.Context, config BPFLoadConfig, objects []VerifiedBPFObject) (BPFLoadResult, error)
}

// LoadVerifiedBPF verifies immutable object digests and snapshots the exact
// bytes before any privileged kernel loading occurs. The backend receives only
// those verified bytes, eliminating path-based verify/load TOCTOU.
func LoadVerifiedBPF(ctx context.Context, backend BPFBackend, config BPFLoadConfig, objects []BPFObjectManifest) (BPFLoadResult, error) {
	if backend == nil {
		return BPFLoadResult{}, fmt.Errorf("BPF backend is required")
	}
	if err := config.Validate(); err != nil {
		return BPFLoadResult{}, fmt.Errorf("validate BPF load config: %w", err)
	}
	verified, err := ReadVerifiedBPFObjects(objects)
	if err != nil {
		return BPFLoadResult{}, fmt.Errorf("verify BPF objects: %w", err)
	}

	result, err := backend.LoadAndAttach(ctx, config, verified)
	if err != nil {
		return BPFLoadResult{}, fmt.Errorf("load and attach BPF objects: %w", err)
	}
	result.ObjectsVerified = true
	if !result.LSMAttached || !result.ConnectAttached || !result.PolicyMapsReady || !result.ArtifactBound ||
		!result.SubtreeScoped || !result.DualStack || !result.FileIOCovered || !result.CredentialCovered ||
		!result.RawSocketCovered || !result.FrozenDuringArm || !result.AtomicCgroupHandle {
		return result, fmt.Errorf("BPF prevention state incomplete: lsm=%t connect=%t maps=%t artifact=%t subtree=%t dualstack=%t fileio=%t credential=%t rawsocket=%t frozen=%t atomic_cgroup=%t",
			result.LSMAttached, result.ConnectAttached, result.PolicyMapsReady, result.ArtifactBound,
			result.SubtreeScoped, result.DualStack, result.FileIOCovered, result.CredentialCovered,
			result.RawSocketCovered, result.FrozenDuringArm, result.AtomicCgroupHandle)
	}
	return result, nil
}
