package nodeshield

import (
	"fmt"
	"runtime"
)

// LinuxHook identifies the kernel control surface expected to back one class
// of pre-action enforcement. These names describe intent; adapters may use
// BPF LSM, cgroup BPF, or another Linux-native mechanism to realize them.
type LinuxHook string

const (
	LinuxHookNetworkConnect LinuxHook = "network_connect"
	LinuxHookFileWrite      LinuxHook = "file_write"
	LinuxHookProcessExec    LinuxHook = "process_exec"
	LinuxHookPrivilege      LinuxHook = "privilege_change"
)

// LinuxHookStatus records whether one security boundary is available and can
// actually reject the covered action before it reaches its target.
type LinuxHookStatus struct {
	Hook      LinuxHook `json:"hook"`
	Available bool      `json:"available"`
	PreAction bool      `json:"pre_action"`
	Backend   string    `json:"backend,omitempty"`
}

// LinuxEnforcementStatus is a runtime capability snapshot for the host.
type LinuxEnforcementStatus struct {
	Platform string            `json:"platform"`
	Hooks    []LinuxHookStatus `json:"hooks"`
}

// Capabilities converts a Linux enforcement probe into the common Node Shield
// capability contract. It only advertises pre-action coverage when every
// required hook is both available and prevention-capable.
func (s LinuxEnforcementStatus) Capabilities() RuntimeCapabilities {
	caps := RuntimeCapabilities{Mode: EnforcementObserveOnly, ArtifactIdentity: true}

	for _, h := range s.Hooks {
		if !h.Available || !h.PreAction {
			continue
		}
		switch h.Hook {
		case LinuxHookNetworkConnect:
			caps.NetworkConnect = true
		case LinuxHookFileWrite:
			caps.FileWrite = true
		case LinuxHookProcessExec:
			caps.ProcessExec = true
		case LinuxHookPrivilege:
			caps.PrivilegeChange = true
		}
	}

	if caps.NetworkConnect || caps.FileWrite || caps.ProcessExec || caps.PrivilegeChange {
		caps.Mode = EnforcementKillOnly
	}
	if caps.NetworkConnect && caps.FileWrite && caps.ProcessExec && caps.PrivilegeChange {
		caps.Mode = EnforcementPreAction
	}
	return caps
}

// ValidateHost rejects non-Linux or incomplete prevention configurations.
func (s LinuxEnforcementStatus) ValidateHost(requirePreAction bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("linux enforcement is unavailable on %s", runtime.GOOS)
	}
	return ValidateRuntimeCapabilities(s.Capabilities(), requirePreAction)
}
