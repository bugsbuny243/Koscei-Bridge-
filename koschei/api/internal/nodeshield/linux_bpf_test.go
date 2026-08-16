//go:build linux

package nodeshield

import "testing"

func fullLinuxBPFProbe() LinuxBPFProbe {
	return LinuxBPFProbe{
		BPFLSMEnabled: true, CgroupBPFEnabled: true, ArtifactBinding: true,
		ExecHookAvailable: true, FileHookAvailable: true, PrivilegeHook: true, ConnectHookAvailable: true,
		ProgramObjectsVerified: true, LSMProgramsAttached: true, ConnectProgramAttached: true, PolicyMapsReady: true,
		CompleteKernelCoverage: true,
	}
}

func TestLinuxBPFProbeRequiresFullCoverageForPreAction(t *testing.T) {
	probe := fullLinuxBPFProbe(); probe.ConnectHookAvailable = false
	if err := ValidateLinuxBPFProbe(probe, true); err == nil { t.Fatal("expected missing connect hook to reject pre-action mode") }
}

func TestLinuxBPFProbeRejectsAvailableButUnloadedPrograms(t *testing.T) {
	probe := fullLinuxBPFProbe(); probe.ProgramObjectsVerified = false
	if err := ValidateLinuxBPFProbe(probe, true); err == nil { t.Fatal("expected unverified BPF objects to reject pre-action mode") }
	if got := probe.Capabilities().Mode; got == EnforcementPreAction { t.Fatal("hook availability alone must never claim pre-action mode") }
}

func TestLinuxBPFProbeRejectsUninitializedPolicyMaps(t *testing.T) {
	probe := fullLinuxBPFProbe(); probe.PolicyMapsReady = false
	if err := ValidateLinuxBPFProbe(probe, true); err == nil { t.Fatal("expected missing policy maps to reject pre-action mode") }
}

func TestLinuxBPFProbeRejectsIncompleteKernelCoverage(t *testing.T) {
	probe := fullLinuxBPFProbe(); probe.CompleteKernelCoverage = false
	if err := ValidateLinuxBPFProbe(probe, true); err == nil { t.Fatal("expected incomplete kernel coverage to reject pre-action mode") }
}

func TestLinuxBPFProbeAcceptsFullCoverage(t *testing.T) {
	probe := fullLinuxBPFProbe()
	if err := ValidateLinuxBPFProbe(probe, true); err != nil { t.Fatalf("expected full linux pre-action coverage: %v", err) }
	if got := probe.Capabilities().Mode; got != EnforcementPreAction { t.Fatalf("expected pre-action mode, got %q", got) }
}

func TestApplyBPFLoadResultDerivesCoverageFromEvidence(t *testing.T) {
	probe := fullLinuxBPFProbe(); probe.CompleteKernelCoverage = false
	probe.ApplyBPFLoadResult(BPFLoadResult{
		ObjectsVerified: true, LSMAttached: true, ConnectAttached: true, PolicyMapsReady: true, ArtifactBound: true,
		SubtreeScoped: true, DualStack: true, FileIOCovered: true, CredentialCovered: true, FrozenDuringArm: true, AtomicCgroupHandle: true,
	})
	if !probe.CompleteKernelCoverage { t.Fatal("expected complete coverage from full backend evidence") }
}
