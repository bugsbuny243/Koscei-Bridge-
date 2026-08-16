package nodeshield

import "testing"

func TestRuntimeAllowsBoundedBehavior(t *testing.T) {
	policy := RuntimePolicy{
		ArtifactSHA256:      "abc123",
		AllowedHosts:        []string{"api.example.com"},
		AllowedWritePaths:   []string{"/data"},
		AllowedExecutables:  []string{"/usr/bin/worker"},
		DenyPrivilegeChange: true,
	}

	cases := []RuntimeEvent{
		{Kind: EventNetworkConnect, Destination: "api.example.com:443"},
		{Kind: EventFileOpen, Path: "/data/result.json", Write: true},
		{Kind: EventProcessExec, Executable: "/usr/bin/worker"},
	}

	for _, event := range cases {
		decision := EvaluateRuntimeEvent(policy, "abc123", event)
		if decision.Action != RuntimeAllow {
			t.Fatalf("expected allow for %#v, got %#v", event, decision)
		}
	}
}

func TestRuntimeDeniesUnexpectedNetwork(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "abc123", AllowedHosts: []string{"api.example.com"}}
	decision := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventNetworkConnect, Destination: "evil.example:443"})
	if decision.Action != RuntimeDeny || decision.RuleID != "NS-RT-NET-001" {
		t.Fatalf("expected network deny, got %#v", decision)
	}
}

func TestRuntimeKillsArtifactMismatch(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "approved"}
	decision := EvaluateRuntimeEvent(policy, "substituted", RuntimeEvent{Kind: EventFileOpen, Path: "/data/a", Write: false})
	if decision.Action != RuntimeKill || decision.RuleID != "NS-RT-PROV-001" {
		t.Fatalf("expected provenance kill, got %#v", decision)
	}
}

func TestRuntimeKillsPrivilegeChange(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "abc123", DenyPrivilegeChange: true}
	decision := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: EventPrivilege})
	if decision.Action != RuntimeKill || decision.RuleID != "NS-RT-AUTH-001" {
		t.Fatalf("expected privilege kill, got %#v", decision)
	}
}

func TestRuntimeUnknownEventFailsClosed(t *testing.T) {
	policy := RuntimePolicy{ArtifactSHA256: "abc123"}
	decision := EvaluateRuntimeEvent(policy, "abc123", RuntimeEvent{Kind: RuntimeEventKind("future_event")})
	if decision.Action != RuntimeDeny || decision.RuleID != "NS-RT-UNK-001" {
		t.Fatalf("expected unknown event deny, got %#v", decision)
	}
}
