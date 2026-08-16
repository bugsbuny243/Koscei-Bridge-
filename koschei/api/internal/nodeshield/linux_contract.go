package nodeshield

import (
	"fmt"
	"runtime"
)

type LinuxHook string

const (
	LinuxHookNetworkConnect LinuxHook = "network_connect"
	LinuxHookFileWrite      LinuxHook = "file_write"
	LinuxHookProcessExec    LinuxHook = "process_exec"
	LinuxHookPrivilege      LinuxHook = "privilege_change"
)

type LinuxHookStatus struct {
	Hook      LinuxHook `json:"hook"`
	Available bool      `json:"available"`
	PreAction bool      `json:"pre_action"`
	Backend   string    `json:"backend,omitempty"`
}

// LinuxEnforcementStatus never synthesizes artifact identity from hook
// discovery. ArtifactIdentityVerified must come from independent workload
// identity evidence produced by the launcher/verifier path.
type LinuxEnforcementStatus struct {
	Platform                 string            `json:"platform"`
	ArtifactIdentityVerified bool              `json:"artifact_identity_verified"`
	Hooks                    []LinuxHookStatus `json:"hooks"`
}

func (s LinuxEnforcementStatus) Capabilities() RuntimeCapabilities {
	caps := RuntimeCapabilities{Mode: EnforcementObserveOnly, ArtifactIdentity: s.ArtifactIdentityVerified}
	for _, h := range s.Hooks {
		if !h.Available || !h.PreAction { continue }
		switch h.Hook {
		case LinuxHookNetworkConnect: caps.NetworkConnect = true
		case LinuxHookFileWrite: caps.FileWrite = true
		case LinuxHookProcessExec: caps.ProcessExec = true
		case LinuxHookPrivilege: caps.PrivilegeChange = true
		}
	}
	if caps.NetworkConnect || caps.FileWrite || caps.ProcessExec || caps.PrivilegeChange { caps.Mode = EnforcementKillOnly }
	if caps.ArtifactIdentity && caps.NetworkConnect && caps.FileWrite && caps.ProcessExec && caps.PrivilegeChange { caps.Mode = EnforcementPreAction }
	return caps
}

func (s LinuxEnforcementStatus) ValidateHost(requirePreAction bool) error {
	if runtime.GOOS != "linux" { return fmt.Errorf("linux enforcement is unavailable on %s", runtime.GOOS) }
	return ValidateRuntimeCapabilities(s.Capabilities(), requirePreAction)
}
