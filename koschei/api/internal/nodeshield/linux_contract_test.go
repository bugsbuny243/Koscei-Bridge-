package nodeshield

import "testing"

func TestLinuxCapabilitiesRequireAllHooksForPreAction(t *testing.T) {
	status := LinuxEnforcementStatus{ArtifactIdentityVerified: true, Hooks: []LinuxHookStatus{
		{Hook: LinuxHookNetworkConnect, Available: true, PreAction: true, Backend: "cgroup-bpf"},
		{Hook: LinuxHookFileWrite, Available: true, PreAction: true, Backend: "bpf-lsm-cgroup"},
		{Hook: LinuxHookProcessExec, Available: true, PreAction: true, Backend: "bpf-lsm-cgroup"},
	}}
	if caps := status.Capabilities(); caps.Mode == EnforcementPreAction { t.Fatalf("partial coverage must not advertise pre-action mode: %#v", caps) }
}

func TestLinuxCapabilitiesRequireArtifactIdentity(t *testing.T) {
	status := LinuxEnforcementStatus{Hooks: []LinuxHookStatus{
		{Hook: LinuxHookNetworkConnect, Available: true, PreAction: true},
		{Hook: LinuxHookFileWrite, Available: true, PreAction: true},
		{Hook: LinuxHookProcessExec, Available: true, PreAction: true},
		{Hook: LinuxHookPrivilege, Available: true, PreAction: true},
	}}
	if caps := status.Capabilities(); caps.Mode == EnforcementPreAction { t.Fatalf("hooks alone must not synthesize artifact identity: %#v", caps) }
}

func TestLinuxCapabilitiesAdvertiseFullPreActionCoverage(t *testing.T) {
	status := LinuxEnforcementStatus{ArtifactIdentityVerified: true, Hooks: []LinuxHookStatus{
		{Hook: LinuxHookNetworkConnect, Available: true, PreAction: true, Backend: "cgroup-bpf"},
		{Hook: LinuxHookFileWrite, Available: true, PreAction: true, Backend: "bpf-lsm-cgroup"},
		{Hook: LinuxHookProcessExec, Available: true, PreAction: true, Backend: "bpf-lsm-cgroup"},
		{Hook: LinuxHookPrivilege, Available: true, PreAction: true, Backend: "bpf-lsm-cgroup"},
	}}
	caps := status.Capabilities()
	if caps.Mode != EnforcementPreAction || !caps.ArtifactIdentity || !caps.NetworkConnect || !caps.FileWrite || !caps.ProcessExec || !caps.PrivilegeChange {
		t.Fatalf("expected full pre-action coverage: %#v", caps)
	}
}

func TestLinuxUnavailableHookDoesNotCountAsCoverage(t *testing.T) {
	status := LinuxEnforcementStatus{ArtifactIdentityVerified: true, Hooks: []LinuxHookStatus{
		{Hook: LinuxHookNetworkConnect, Available: true, PreAction: true},
		{Hook: LinuxHookFileWrite, Available: false, PreAction: true},
	}}
	if caps := status.Capabilities(); caps.FileWrite { t.Fatalf("unavailable hook must not count as coverage: %#v", caps) }
}
