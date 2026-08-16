//go:build linux

package nodeshield

import (
	"fmt"
	"runtime"
)

// LinuxBPFProbe describes the kernel/runtime features a concrete Linux adapter
// discovered at startup. It is intentionally explicit so unsupported kernels
// cannot silently downgrade prevention guarantees.
type LinuxBPFProbe struct {
	KernelRelease       string `json:"kernel_release,omitempty"`
	BPFLSMEnabled       bool   `json:"bpf_lsm_enabled"`
	CgroupBPFEnabled    bool   `json:"cgroup_bpf_enabled"`
	ArtifactBinding     bool   `json:"artifact_binding"`
	ExecHookAvailable   bool   `json:"exec_hook_available"`
	FileHookAvailable   bool   `json:"file_hook_available"`
	PrivilegeHook       bool   `json:"privilege_hook_available"`
	ConnectHookAvailable bool  `json:"connect_hook_available"`
}

// Capabilities converts the probed Linux hook coverage into the common Node
// Shield runtime capability contract. Full pre-action mode is only declared
// when every required security boundary is present.
func (p LinuxBPFProbe) Capabilities() RuntimeCapabilities {
	fullPreAction := p.BPFLSMEnabled && p.CgroupBPFEnabled && p.ArtifactBinding &&
		p.ExecHookAvailable && p.FileHookAvailable && p.PrivilegeHook && p.ConnectHookAvailable

	mode := EnforcementObserveOnly
	if fullPreAction {
		mode = EnforcementPreAction
	}

	return RuntimeCapabilities{
		Mode:              mode,
		ArtifactIdentity: p.ArtifactBinding,
		NetworkConnect:    p.CgroupBPFEnabled && p.ConnectHookAvailable,
		FileWrite:         p.BPFLSMEnabled && p.FileHookAvailable,
		ProcessExec:       p.BPFLSMEnabled && p.ExecHookAvailable,
		PrivilegeChange:  p.BPFLSMEnabled && p.PrivilegeHook,
	}
}

// ValidateLinuxBPFProbe rejects incomplete or contradictory Linux prevention
// claims before a runtime guard is allowed to start in pre-action mode.
func ValidateLinuxBPFProbe(p LinuxBPFProbe, requirePreAction bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("linux BPF enforcement is only supported on linux")
	}
	if requirePreAction && !p.BPFLSMEnabled {
		return fmt.Errorf("pre-action enforcement requires BPF LSM support")
	}
	if requirePreAction && !p.CgroupBPFEnabled {
		return fmt.Errorf("pre-action network enforcement requires cgroup BPF support")
	}
	return ValidateRuntimeCapabilities(p.Capabilities(), requirePreAction)
}
