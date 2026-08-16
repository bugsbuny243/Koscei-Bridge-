//go:build linux

package nodeshield

import "testing"

func TestLinuxBPFProbeRequiresFullCoverageForPreAction(t *testing.T) {
	probe := LinuxBPFProbe{
		BPFLSMEnabled:        true,
		CgroupBPFEnabled:     true,
		ArtifactBinding:      true,
		ExecHookAvailable:    true,
		FileHookAvailable:    true,
		PrivilegeHook:        true,
		ConnectHookAvailable: false,
	}
	if err := ValidateLinuxBPFProbe(probe, true); err == nil {
		t.Fatal("expected missing connect hook to reject pre-action mode")
	}
}

func TestLinuxBPFProbeAcceptsFullCoverage(t *testing.T) {
	probe := LinuxBPFProbe{
		BPFLSMEnabled:        true,
		CgroupBPFEnabled:     true,
		ArtifactBinding:      true,
		ExecHookAvailable:    true,
		FileHookAvailable:    true,
		PrivilegeHook:        true,
		ConnectHookAvailable: true,
	}
	if err := ValidateLinuxBPFProbe(probe, true); err != nil {
		t.Fatalf("expected full linux pre-action coverage: %v", err)
	}
	if got := probe.Capabilities().Mode; got != EnforcementPreAction {
		t.Fatalf("expected pre-action mode, got %q", got)
	}
}
