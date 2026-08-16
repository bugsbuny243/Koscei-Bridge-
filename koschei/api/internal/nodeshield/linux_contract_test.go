package nodeshield

import "testing"

func TestLinuxCapabilitiesRequireAllHooksForPreAction(t *testing.T) {
	status := LinuxEnforcementStatus{Hooks: []LinuxHookStatus{
		{Hook: LinuxHookNetworkConnect, Available: true, PreAction: true, Backend: "cgroup-bpf"},
		{Hook: LinuxHookFileWrite, Available: true, PreAction: true, Backend: "bpf-lsm"},
		{Hook: LinuxHookProcessExec, Available: true, PreAction: true, Backend: "bpf-lsm"},
	}}
	caps := status.Capabilities()
	if caps.Mode == EnforcementPreAction {
		t.Fatalf("partial coverage must not advertise pre-action mode: %#v", caps)
	}
}

func TestLinuxCapabilitiesAdvertiseFullPreActionCoverage(t *testing.T) {
	status := LinuxEnforcementStatus{Hooks: []LinuxHookStatus{
		{Hook: LinuxHookNetworkConnect, Available: true, PreAction: true, Backend: "cgroup-bpf"},
		{Hook: LinuxHookFileWrite, Available: true, PreAction: true, Backend: "bpf-lsm"},
		{Hook: LinuxHookProcessExec, Available: true, PreAction: true, Backend: "bpf-lsm"},
		{Hook: LinuxHookPrivilege, Available: true, PreAction: true, Backend: "bpf-lsm"},
	}}
	caps := status.Capabilities()
	if caps.Mode != EnforcementPreAction || !caps.NetworkConnect || !caps.FileWrite || !caps.ProcessExec || !caps.PrivilegeChange {
		t.Fatalf("expected full pre-action coverage: %#v", caps)
	}
}

func TestLinuxUnavailableHookDoesNotCountAsCoverage(t *testing.T) {
	status := LinuxEnforcementStatus{Hooks: []LinuxHookStatus{
		{Hook: LinuxHookNetworkConnect, Available: true, PreAction: true},
		{Hook: LinuxHookFileWrite, Available: false, PreAction: true},
	}}
	caps := status.Capabilities()
	if caps.FileWrite {
		t.Fatalf("unavailable hook must not count as coverage: %#v", caps)
	}
}
