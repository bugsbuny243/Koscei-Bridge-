//go:build linux

package nodeshield

import (
	"fmt"
	"runtime"
)

type LinuxBPFProbe struct {
	KernelRelease          string `json:"kernel_release,omitempty"`
	BPFLSMEnabled          bool   `json:"bpf_lsm_enabled"`
	CgroupBPFEnabled       bool   `json:"cgroup_bpf_enabled"`
	ArtifactBinding        bool   `json:"artifact_binding"`
	ExecHookAvailable      bool   `json:"exec_hook_available"`
	FileHookAvailable      bool   `json:"file_hook_available"`
	PrivilegeHook          bool   `json:"privilege_hook_available"`
	ConnectHookAvailable   bool   `json:"connect_hook_available"`
	ProgramObjectsVerified bool   `json:"program_objects_verified"`
	LSMProgramsAttached    bool   `json:"lsm_programs_attached"`
	ConnectProgramAttached bool   `json:"connect_program_attached"`
	PolicyMapsReady        bool   `json:"policy_maps_ready"`
	CompleteKernelCoverage bool   `json:"complete_kernel_coverage"`
}

func (p *LinuxBPFProbe) ApplyBPFLoadResult(result BPFLoadResult) {
	if p == nil { return }
	p.ProgramObjectsVerified = result.ObjectsVerified
	p.LSMProgramsAttached = result.LSMAttached
	p.ConnectProgramAttached = result.ConnectAttached
	p.PolicyMapsReady = result.PolicyMapsReady
	p.ArtifactBinding = p.ArtifactBinding && result.ArtifactBound
	p.CompleteKernelCoverage = result.SubtreeScoped && result.DualStack && result.FileIOCovered &&
		result.CredentialCovered && result.FrozenDuringArm && result.AtomicCgroupHandle
}

func (p LinuxBPFProbe) Capabilities() RuntimeCapabilities {
	loaded := p.ProgramObjectsVerified && p.LSMProgramsAttached && p.ConnectProgramAttached && p.PolicyMapsReady
	fullPreAction := p.CompleteKernelCoverage && p.BPFLSMEnabled && p.CgroupBPFEnabled && p.ArtifactBinding && loaded &&
		p.ExecHookAvailable && p.FileHookAvailable && p.PrivilegeHook && p.ConnectHookAvailable
	mode := EnforcementObserveOnly
	if fullPreAction { mode = EnforcementPreAction }
	return RuntimeCapabilities{
		Mode: mode, ArtifactIdentity: p.ArtifactBinding,
		NetworkConnect: fullPreAction, FileWrite: fullPreAction,
		ProcessExec: fullPreAction, PrivilegeChange: fullPreAction,
	}
}

func ValidateLinuxBPFProbe(p LinuxBPFProbe, requirePreAction bool) error {
	if runtime.GOOS != "linux" { return fmt.Errorf("linux BPF enforcement is only supported on linux") }
	if requirePreAction && !p.BPFLSMEnabled { return fmt.Errorf("pre-action enforcement requires BPF LSM support") }
	if requirePreAction && !p.CgroupBPFEnabled { return fmt.Errorf("pre-action network enforcement requires cgroup BPF support") }
	if requirePreAction && !p.ProgramObjectsVerified { return fmt.Errorf("pre-action enforcement requires verified BPF program objects") }
	if requirePreAction && (!p.LSMProgramsAttached || !p.ConnectProgramAttached) { return fmt.Errorf("pre-action enforcement requires all BPF programs to be attached") }
	if requirePreAction && !p.PolicyMapsReady { return fmt.Errorf("pre-action enforcement requires initialized artifact-bound policy maps") }
	if requirePreAction && !p.CompleteKernelCoverage { return fmt.Errorf("pre-action enforcement requires complete adversarial kernel coverage") }
	return ValidateRuntimeCapabilities(p.Capabilities(), requirePreAction)
}
