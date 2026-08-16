package nodeshield

import (
	"strings"
	"testing"
)

const testSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestScanBlocksIsolationCollapse(t *testing.T) {
	r := Scan(WorkloadManifest{Name: "bad-workload", ArtifactSHA256: testSHA, Privileged: true, DockerSocket: true, ReadOnlyRootFS: true, OutboundHosts: []string{"api.example.com:443"}})
	if r.Verdict != VerdictBlock { t.Fatalf("expected block, got %s", r.Verdict) }
}

func TestScanWarnsOnWeakenedBoundaries(t *testing.T) {
	r := Scan(WorkloadManifest{Name: "risky-workload", ArtifactSHA256: testSHA, HostNetwork: true, ReadOnlyRootFS: true, OutboundHosts: []string{"api.example.com:443"}})
	if r.Verdict != VerdictWarn { t.Fatalf("expected warn, got %s", r.Verdict) }
}

func TestScanAllowsConstrainedWorkload(t *testing.T) {
	r := Scan(WorkloadManifest{Name: "constrained-workload", ArtifactSHA256: testSHA, ReadOnlyRootFS: true, OutboundHosts: []string{"api.example.com:443"}})
	if r.Verdict != VerdictAllow { t.Fatalf("expected allow, got %s with findings %#v", r.Verdict, r.Findings) }
}

func TestScanRejectsInvalidDigest(t *testing.T) {
	r := Scan(WorkloadManifest{Name: "bad-digest", ArtifactSHA256: "deadbeef", ReadOnlyRootFS: true, OutboundHosts: []string{"api.example.com:443"}})
	if r.Verdict != VerdictWarn { t.Fatalf("expected warn for invalid digest, got %s", r.Verdict) }
}

func TestScanBlocksParentOfSensitiveMount(t *testing.T) {
	r := Scan(WorkloadManifest{Name: "host-root", ArtifactSHA256: testSHA, ReadOnlyRootFS: true, OutboundHosts: []string{"api.example.com:443"}, Mounts: []Mount{{Type: "bind", Source: "/", Target: "/host"}}})
	if r.Verdict != VerdictBlock { t.Fatalf("expected block for host root bind, got %s", r.Verdict) }
}

func TestScanBlocksAllCapability(t *testing.T) {
	r := Scan(WorkloadManifest{Name: "all-caps", ArtifactSHA256: testSHA, ReadOnlyRootFS: true, OutboundHosts: []string{"api.example.com:443"}, Capabilities: []string{"CAP_ALL"}})
	if r.Verdict != VerdictBlock { t.Fatalf("expected block for CAP_ALL, got %s", r.Verdict) }
}

func TestScanBlocksRawDevice(t *testing.T) {
	r := Scan(WorkloadManifest{Name: "raw-device", ArtifactSHA256: testSHA, ReadOnlyRootFS: true, OutboundHosts: []string{"api.example.com:443"}, Devices: []DeviceMapping{{HostPath: "/dev/sda", ContainerPath: "/dev/x"}}})
	if r.Verdict != VerdictBlock { t.Fatalf("expected block for raw device, got %s", r.Verdict) }
}

func TestScanRejectsBlankOutboundEntries(t *testing.T) {
	r := Scan(WorkloadManifest{Name: "blank-egress", ArtifactSHA256: testSHA, ReadOnlyRootFS: true, OutboundHosts: []string{"   "}})
	if r.Verdict != VerdictWarn { t.Fatalf("expected warn for blank egress boundary, got %s", r.Verdict) }
	found := false
	for _, f := range r.Findings { if f.ID == "NS-NET-002" { found = true } }
	if !found { t.Fatalf("expected NS-NET-002, got %#v", r.Findings) }
}

func TestSHAValidationAcceptsUpperHex(t *testing.T) {
	if !validSHA256(strings.Repeat("A", 64)) { t.Fatal("expected uppercase hex SHA-256 to be accepted") }
}
