package nodeshield

import "testing"

func TestRuntimeAllowsBoundedBehavior(t *testing.T) {
	policy := RuntimePolicy{
		ArtifactSHA256: "abc123",
		AllowedHosts: []string{"api.example.com:443"},
		AllowedWritePaths: []string{"/data"},
		AllowedExecutables: []string{"/usr/bin/worker"},
		DenyPrivilegeChange: true,
	}
	cases := []RuntimeEvent{
		{Kind: EventNetworkConnect, Destination: "api.example.com:443"},
		{Kind: EventFileOpen, Path: "/data/link/result.json", ResolvedPath: "/data/result.json", PathIdentityVerified: true, Write: true},
		{Kind: EventProcessExec, Executable: "/usr/bin/worker", ResolvedExecutable: "/usr/bin/worker", ExecutableIdentityVerified: true},
	}
	for _, event := range cases {
		if d := EvaluateRuntimeEvent(policy, "abc123", event); d.Action != RuntimeAllow { t.Fatalf("expected allow for %#v, got %#v", event, d) }
	}
}

func TestRuntimePreservesPortBoundary(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "abc123", AllowedHosts: []string{"api.example.com:443"}}
	if d := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventNetworkConnect, Destination: "api.example.com:22"}); d.Action != RuntimeDeny {
		t.Fatalf("port 22 must not inherit port 443 authority: %#v", d)
	}
}

func TestRuntimeDeniesUnexpectedNetwork(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "abc123", AllowedHosts: []string{"api.example.com:443"}}
	d := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventNetworkConnect, Destination: "evil.example:443"})
	if d.Action != RuntimeDeny || d.RuleID != "NS-RT-NET-001" { t.Fatalf("expected network deny, got %#v", d) }
}

func TestRuntimeRejectsInvalidEndpointForms(t *testing.T) {
	for _, raw := range []string{"garbage", "*:443", "example.com:notaport", "example.com:0", "bad..example:443"} {
		if got := normalizePolicyEndpoint(raw); got != "" { t.Fatalf("invalid endpoint %q normalized to %q", raw, got) }
	}
	if got := normalizePolicyEndpoint("*.example.com:443"); got == "" { t.Fatal("controlled wildcard endpoint should be accepted") }
}

func TestRuntimeWildcardDoesNotAllowApex(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "abc123", AllowedHosts: []string{"*.example.com:443"}}
	if d := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventNetworkConnect, Destination: "api.example.com:443"}); d.Action != RuntimeAllow { t.Fatalf("expected subdomain allow, got %#v", d) }
	if d := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventNetworkConnect, Destination: "example.com:443"}); d.Action != RuntimeDeny { t.Fatalf("expected wildcard not to authorize apex, got %#v", d) }
}

func TestRuntimeRejectsUnverifiedOrEscapedWriteTarget(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "abc123", AllowedWritePaths: []string{"/data"}}
	if d := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventFileOpen, Path: "/data/link/config", Write: true}); d.RuleID != "NS-RT-FS-002" { t.Fatalf("expected unresolved path deny, got %#v", d) }
	if d := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventFileOpen, Path: "/data/link/config", ResolvedPath: "/etc/config", PathIdentityVerified: true, Write: true}); d.Action != RuntimeDeny { t.Fatalf("expected resolved escape deny, got %#v", d) }
}

func TestRuntimeRejectsUnverifiedOrEscapedExecutable(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "abc123", AllowedExecutables: []string{"/usr/bin/worker"}}
	if d := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventProcessExec, Executable: "/usr/bin/worker"}); d.RuleID != "NS-RT-PROC-002" { t.Fatalf("expected unverified exec identity deny, got %#v", d) }
	if d := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventProcessExec, Executable: "/usr/bin/worker", ResolvedExecutable: "/tmp/attacker", ExecutableIdentityVerified: true}); d.Action != RuntimeDeny { t.Fatalf("lexical allowed path must not authorize resolved escape: %#v", d) }
}

func TestRuntimeRejectsRootWriteBoundary(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "abc123", AllowedWritePaths: []string{"/"}}
	d := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventFileOpen, ResolvedPath: "/tmp/result", PathIdentityVerified: true, Write: true})
	if d.Action != RuntimeDeny { t.Fatalf("root write boundary must be rejected, got %#v", d) }
}

func TestRuntimeKillsArtifactMismatch(t *testing.T) {
	d := EvaluateRuntimeEvent(RuntimePolicy{ArtifactSHA256: "approved"}, "substituted", RuntimeEvent{Kind: EventFileOpen, Path: "/data/a", Write: false})
	if d.Action != RuntimeKill || d.RuleID != "NS-RT-PROV-001" { t.Fatalf("expected provenance kill, got %#v", d) }
}

func TestRuntimeKillsPrivilegeChange(t *testing.T) {
	d := EvaluateRuntimeEvent(RuntimePolicy{ArtifactSHA256: "abc123", DenyPrivilegeChange: true}, "abc123", RuntimeEvent{Kind: EventPrivilege})
	if d.Action != RuntimeKill || d.RuleID != "NS-RT-AUTH-001" { t.Fatalf("expected privilege kill, got %#v", d) }
}

func TestRuntimeUnknownEventFailsClosed(t *testing.T) {
	d := EvaluateRuntimeEvent(RuntimePolicy{ArtifactSHA256: "abc123"}, "abc123", RuntimeEvent{Kind: RuntimeEventKind("future_event")})
	if d.Action != RuntimeDeny || d.RuleID != "NS-RT-UNK-001" { t.Fatalf("expected unknown event deny, got %#v", d) }
}
