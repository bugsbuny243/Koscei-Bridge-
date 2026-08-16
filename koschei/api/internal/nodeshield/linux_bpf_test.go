//go:build linux

package nodeshield

import "testing"

func fullLinuxBPFProbe() LinuxBPFProbe {
	return LinuxBPFProbe{
		BPFLSMEnabled:          true,
		CgroupBPFEnabled:       true,
		ArtifactBinding:        true,
		ExecHookAvailable:      true,
		FileHookAvailable:      true,
		PrivilegeHook:          true,
		ConnectHookAvailable:   true,
		ProgramObjectsVerified: true,
		LSMProgramsAttached:    true,
		ConnectProgramAttached: true,
		PolicyMapsReady:        true,
	}
}

func TestLinuxBPFProbeRequiresFullCoverageForPreAction(t *testing.T) {
	probe := fullLinuxBPFProbe()
	probe.ConnectHookAvailable = false
	if err := ValidateLinuxBPFProbe(probe, true); err == nil {
		t.Fatal("expected missing connect hook to reject pre-action mode")
	}
}

func TestLinuxBPFProbeRejectsAvailableButUnloadedPrograms(t *testing.T) {
	probe := fullLinuxBPFProbe()
	probe.ProgramObjectsVerified = false
	if err := ValidateLinuxBPFProbe(probe, true); err == nil {
		t.Fatal("expected unverified BPF objects to reject pre-action mode")
	}
	if got := probe.Capabilities().Mode; got == EnforcementPreAction {
		t.Fatal("hook availability alone must never claim pre-action mode")
	}
}

func TestLinuxBPFProbeRejectsUninitializedPolicyMaps(t *testing.T) {
	probe := fullLinuxBPFProbe()
	probe.PolicyMapsReady = false
	if err := ValidateLinuxBPFProbe(probe, true); err == nil {
		t.Fatal("expected missing policy maps to reject pre-action mode")
	}
}

func TestLinuxBPFProbeAcceptsFullCoverage(t *testing.T) {
	probe := fullLinuxBPFProbe()
	if err := ValidateLinuxBPFProbe(probe, true); err != nil {
		t.Fatalf("expected full linux pre-action coverage: %v", err)
	}
	if got := probe.Capabilities().Mode; got != EnforcementPreAction {
		t.Fatalf("expected pre-action mode, got %q", got)
	}
}
