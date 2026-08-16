package nodeshield

import "testing"

func TestScanBlocksIsolationCollapse(t *testing.T) {
	r := Scan(WorkloadManifest{
		Name:           "bad-workload",
		ArtifactSHA256: "abc123",
		Privileged:     true,
		DockerSocket:   true,
		ReadOnlyRootFS: true,
		OutboundHosts:  []string{"api.example.com"},
	})
	if r.Verdict != VerdictBlock {
		t.Fatalf("expected block, got %s", r.Verdict)
	}
}

func TestScanWarnsOnWeakenedBoundaries(t *testing.T) {
	r := Scan(WorkloadManifest{
		Name:           "risky-workload",
		ArtifactSHA256: "abc123",
		HostNetwork:    true,
		ReadOnlyRootFS: true,
		OutboundHosts:  []string{"api.example.com"},
	})
	if r.Verdict != VerdictWarn {
		t.Fatalf("expected warn, got %s", r.Verdict)
	}
}

func TestScanAllowsConstrainedWorkload(t *testing.T) {
	r := Scan(WorkloadManifest{
		Name:           "constrained-workload",
		ArtifactSHA256: "abc123",
		ReadOnlyRootFS: true,
		OutboundHosts:  []string{"api.example.com"},
	})
	if r.Verdict != VerdictAllow {
		t.Fatalf("expected allow, got %s with findings %#v", r.Verdict, r.Findings)
	}
	if r.Score != 100 {
		t.Fatalf("expected score 100, got %d", r.Score)
	}
}
