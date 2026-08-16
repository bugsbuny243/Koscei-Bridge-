//go:build linux

package nodeshield

import (
	"fmt"
	"runtime"
)

// LinuxBPFProbe describes the kernel/runtime features and loaded-program state
// a concrete Linux adapter discovered at startup. Hook availability alone is
// never enough to claim prevention: the exact BPF objects must be verified,
// attached, and have artifact-bound policy maps populated first.
type LinuxBPFProbe struct {
	KernelRelease         string `json:"kernel_release,omitempty"`
	BPFLSMEnabled         bool   `json:"bpf_lsm_enabled"`
	CgroupBPFEnabled      bool   `json:"cgroup_bpf_enabled"`
	ArtifactBinding       bool   `json:"artifact_binding"`
	ExecHookAvailable     bool   `json:"exec_hook_available"`
	FileHookAvailable     bool   `json:"file_hook_available"`
	PrivilegeHook         bool   `json:"privilege_hook_available"`
	ConnectHookAvailable  bool   `json:"connect_hook_available"`
	ProgramObjectsVerified bool  `json:"program_objects_verified"`
	LSMProgramsAttached   bool   `json:"lsm_programs_attached"`
	ConnectProgramAttached bool  `json:"connect_program_attached"`
	PolicyMapsReady       bool   `json:"policy_maps_ready"`
}

// Capabilities converts the probed Linux hook coverage into the common Node
// Shield runtime capability contract. Full pre-action mode is only declared
// when every required security boundary exists and the loaded enforcement
// state is cryptographically/operationally bound to the approved workload.
func (p LinuxBPFProbe) Capabilities() RuntimeCapabilities {
	loaded := p.ProgramObjectsVerified && p.LSMProgramsAttached && p.ConnectProgramAttached && p.PolicyMapsReady
	fullPreAction := p.BPFLSMEnabled && p.CgroupBPFEnabled && p.ArtifactBinding && loaded &&
		p.ExecHookAvailable && p.FileHookAvailable && p.PrivilegeHook && p.ConnectHookAvailable

	mode := EnforcementObserveOnly
	if fullPreAction {
		mode = EnforcementPreAction
	}

	return RuntimeCapabilities{
		Mode:              mode,
		ArtifactIdentity: p.ArtifactBinding,
		NetworkConnect:    loaded && p.CgroupBPFEnabled && p.ConnectHookAvailable,
		FileWrite:         loaded && p.BPFLSMEnabled && p.FileHookAvailable,
		ProcessExec:       loaded && p.BPFLSMEnabled && p.ExecHookAvailable,
		PrivilegeChange:  loaded && p.BPFLSMEnabled && p.PrivilegeHook,
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
	if requirePreAction && !p.ProgramObjectsVerified {
		return fmt.Errorf("pre-action enforcement requires verified BPF program objects")
	}
	if requirePreAction && (!p.LSMProgramsAttached || !p.ConnectProgramAttached) {
		return fmt.Errorf("pre-action enforcement requires all BPF programs to be attached")
	}
	if requirePreAction && !p.PolicyMapsReady {
		return fmt.Errorf("pre-action enforcement requires initialized artifact-bound policy maps")
	}
	return ValidateRuntimeCapabilities(p.Capabilities(), requirePreAction)
}
