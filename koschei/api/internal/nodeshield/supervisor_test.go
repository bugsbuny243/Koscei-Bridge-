package nodeshield

import (
	"context"
	"errors"
	"testing"
)

type fakeAudit struct {
	decisions []RuntimeDecision
	err       error
}

func (f *fakeAudit) RecordRuntimeDecision(_ context.Context, _ string, _ RuntimeEvent, d RuntimeDecision) error {
	f.decisions = append(f.decisions, d)
	return f.err
}

type fakeEnforcer struct {
	denied int
	killed int
	err    error
}

func (f *fakeEnforcer) Deny(_ context.Context, _ string, _ RuntimeEvent, _ RuntimeDecision) error {
	f.denied++
	return f.err
}

func (f *fakeEnforcer) Kill(_ context.Context, _ string, _ RuntimeDecision) error {
	f.killed++
	return f.err
}

func TestSupervisorAllowsWithoutMutation(t *testing.T) {
	audit := &fakeAudit{}
	enforcer := &fakeEnforcer{}
	s := Supervisor{
		WorkloadID:             "w1",
		ObservedArtifactSHA256: "abc",
		Policy: RuntimePolicy{
			ArtifactSHA256: "abc",
			AllowedHosts:   []string{"api.example.com"},
		},
		Audit: audit, Enforcer: enforcer,
	}

	d, err := s.Handle(context.Background(), RuntimeEvent{Kind: EventNetworkConnect, Destination: "api.example.com:443"})
	if err != nil || d.Action != RuntimeAllow {
		t.Fatalf("expected allow, got decision=%#v err=%v", d, err)
	}
	if enforcer.denied != 0 || enforcer.killed != 0 {
		t.Fatalf("allow must not mutate platform: %#v", enforcer)
	}
}

func TestSupervisorEnforcesDeny(t *testing.T) {
	audit := &fakeAudit{}
	enforcer := &fakeEnforcer{}
	s := Supervisor{
		WorkloadID:             "w1",
		ObservedArtifactSHA256: "abc",
		Policy: RuntimePolicy{ArtifactSHA256: "abc", AllowedHosts: []string{"api.example.com"}},
		Audit: audit, Enforcer: enforcer,
	}

	d, err := s.Handle(context.Background(), RuntimeEvent{Kind: EventNetworkConnect, Destination: "evil.example:443"})
	if err != nil || d.Action != RuntimeDeny || enforcer.denied != 1 {
		t.Fatalf("expected enforced deny, decision=%#v enforcer=%#v err=%v", d, enforcer, err)
	}
}

func TestSupervisorEnforcesKillOnArtifactMismatch(t *testing.T) {
	audit := &fakeAudit{}
	enforcer := &fakeEnforcer{}
	s := Supervisor{
		WorkloadID:             "w1",
		ObservedArtifactSHA256: "tampered",
		Policy: RuntimePolicy{ArtifactSHA256: "approved"},
		Audit: audit, Enforcer: enforcer,
	}

	d, err := s.Handle(context.Background(), RuntimeEvent{Kind: EventFileOpen, Path: "/tmp/x"})
	if err != nil || d.Action != RuntimeKill || enforcer.killed != 1 {
		t.Fatalf("expected enforced kill, decision=%#v enforcer=%#v err=%v", d, enforcer, err)
	}
}

func TestSupervisorFailsClosedWithoutEnforcer(t *testing.T) {
	s := Supervisor{
		WorkloadID:             "w1",
		ObservedArtifactSHA256: "abc",
		Policy: RuntimePolicy{ArtifactSHA256: "abc", AllowedHosts: []string{"api.example.com"}},
		Audit: &fakeAudit{},
	}

	d, err := s.Handle(context.Background(), RuntimeEvent{Kind: EventNetworkConnect, Destination: "evil.example:443"})
	if d.Action != RuntimeDeny || err == nil {
		t.Fatalf("expected deny with fail-closed error, decision=%#v err=%v", d, err)
	}
}

func TestSupervisorFailsClosedOnAuditFailureForBlockingDecision(t *testing.T) {
	s := Supervisor{
		WorkloadID:             "w1",
		ObservedArtifactSHA256: "abc",
		Policy: RuntimePolicy{ArtifactSHA256: "abc", AllowedHosts: []string{"api.example.com"}},
		Audit: &fakeAudit{err: errors.New("disk unavailable")},
		Enforcer: &fakeEnforcer{},
	}

	d, err := s.Handle(context.Background(), RuntimeEvent{Kind: EventNetworkConnect, Destination: "evil.example:443"})
	if d.Action != RuntimeDeny || err == nil {
		t.Fatalf("expected audit failure to stop enforcement path, decision=%#v err=%v", d, err)
	}
}
