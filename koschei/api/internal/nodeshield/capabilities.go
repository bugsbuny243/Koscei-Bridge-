package nodeshield

import "fmt"

// EnforcementMode describes what the underlying collector/enforcer pair can
// actually guarantee. ObserveOnly may report violations after they happened;
// PreActionDeny can stop a covered action before it reaches the target.
type EnforcementMode string

const (
	EnforcementObserveOnly EnforcementMode = "observe_only"
	EnforcementKillOnly    EnforcementMode = "kill_only"
	EnforcementPreAction   EnforcementMode = "pre_action_deny"
)

// RuntimeCapabilities are declared by a platform adapter. The guard validates
// them before startup so an observational collector cannot be mistaken for a
// prevention-capable one.
type RuntimeCapabilities struct {
	Mode              EnforcementMode `json:"mode"`
	NetworkConnect    bool            `json:"network_connect"`
	FileWrite         bool            `json:"file_write"`
	ProcessExec       bool            `json:"process_exec"`
	PrivilegeChange  bool            `json:"privilege_change"`
	ArtifactIdentity bool            `json:"artifact_identity"`
}

// CapabilitySource is implemented by collectors that can describe their
// enforcement coverage (for example an eBPF/LSM adapter or OCI runtime hook).
type CapabilitySource interface {
	Capabilities() RuntimeCapabilities
}

// ValidateRuntimeCapabilities fails closed for configurations that would make
// Node Shield claim stronger prevention than the platform can provide.
func ValidateRuntimeCapabilities(c RuntimeCapabilities, requirePreAction bool) error {
	switch c.Mode {
	case EnforcementObserveOnly, EnforcementKillOnly, EnforcementPreAction:
	default:
		return fmt.Errorf("unknown runtime enforcement mode %q", c.Mode)
	}

	if !c.ArtifactIdentity {
		return fmt.Errorf("runtime collector must provide artifact identity binding")
	}

	if requirePreAction {
		if c.Mode != EnforcementPreAction {
			return fmt.Errorf("pre-action enforcement required, collector mode is %q", c.Mode)
		}
		if !c.NetworkConnect || !c.FileWrite || !c.ProcessExec || !c.PrivilegeChange {
			return fmt.Errorf("pre-action enforcement requires network, file-write, process-exec, and privilege-change coverage")
		}
	}

	return nil
}
