//go:build !linux

package nodeshield

import "fmt"

// LinuxBPFProbe exists on non-Linux builds so the common package still
// compiles, but it can never claim kernel prevention support.
type LinuxBPFProbe struct {
	KernelRelease        string `json:"kernel_release,omitempty"`
	BPFLSMEnabled        bool   `json:"bpf_lsm_enabled"`
	CgroupBPFEnabled     bool   `json:"cgroup_bpf_enabled"`
	ArtifactBinding      bool   `json:"artifact_binding"`
	ExecHookAvailable    bool   `json:"exec_hook_available"`
	FileHookAvailable    bool   `json:"file_hook_available"`
	PrivilegeHook        bool   `json:"privilege_hook_available"`
	ConnectHookAvailable bool   `json:"connect_hook_available"`
}

func (LinuxBPFProbe) Capabilities() RuntimeCapabilities {
	return RuntimeCapabilities{Mode: EnforcementObserveOnly}
}

func ValidateLinuxBPFProbe(LinuxBPFProbe, bool) error {
	return fmt.Errorf("linux BPF enforcement is unavailable on this platform")
}
