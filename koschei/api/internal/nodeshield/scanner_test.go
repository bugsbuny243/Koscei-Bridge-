package nodeshield

import (
	"strings"
	"testing"
)

const testSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func safeManifest(name string) WorkloadManifest {
	return WorkloadManifest{Name:name, ArtifactSHA256:testSHA, UserIdentityVerified:true, ReadOnlyRootFS:true, OutboundHosts:[]string{"api.example.com:443"}}
}

func TestScanBlocksIsolationCollapse(t *testing.T) {
	m:=safeManifest("bad-workload"); m.Privileged=true; m.DockerSocket=true
	if r:=Scan(m); r.Verdict!=VerdictBlock { t.Fatalf("expected block, got %s",r.Verdict) }
}
func TestScanWarnsOnWeakenedBoundaries(t *testing.T) { m:=safeManifest("risky"); m.HostNetwork=true; if r:=Scan(m); r.Verdict!=VerdictWarn { t.Fatalf("expected warn, got %s",r.Verdict) } }
func TestScanAllowsConstrainedWorkload(t *testing.T) { if r:=Scan(safeManifest("safe")); r.Verdict!=VerdictAllow { t.Fatalf("expected allow, got %s %#v",r.Verdict,r.Findings) } }
func TestScanRejectsInvalidDigest(t *testing.T) { m:=safeManifest("bad-digest"); m.ArtifactSHA256="deadbeef"; if r:=Scan(m); r.Verdict!=VerdictWarn { t.Fatalf("expected warn, got %s",r.Verdict) } }
func TestScanBlocksParentOfSensitiveMount(t *testing.T) { m:=safeManifest("host-root"); m.Mounts=[]Mount{{Type:"bind",Source:"/",Target:"/host"}}; if r:=Scan(m); r.Verdict!=VerdictBlock { t.Fatalf("expected block, got %s",r.Verdict) } }
func TestScanBlocksCanonicalRunDockerSocket(t *testing.T) { m:=safeManifest("docker-sock"); m.Mounts=[]Mount{{Type:"bind",Source:"/run/docker.sock",Target:"/run/docker.sock"}}; if r:=Scan(m); r.Verdict!=VerdictBlock { t.Fatalf("expected block for /run/docker.sock, got %s",r.Verdict) } }
func TestScanBlocksAllCapability(t *testing.T) { m:=safeManifest("all-caps"); m.Capabilities=[]string{"CAP_ALL"}; if r:=Scan(m); r.Verdict!=VerdictBlock { t.Fatalf("expected block, got %s",r.Verdict) } }
func TestScanBlocksRawDevice(t *testing.T) { m:=safeManifest("raw-device"); m.Devices=[]DeviceMapping{{HostPath:"/dev/sda",ContainerPath:"/dev/x"}}; if r:=Scan(m); r.Verdict!=VerdictBlock { t.Fatalf("expected block, got %s",r.Verdict) } }
func TestScanRejectsBlankOutboundEntries(t *testing.T) { m:=safeManifest("blank-egress"); m.OutboundHosts=[]string{"   "}; r:=Scan(m); if r.Verdict!=VerdictWarn { t.Fatalf("expected warn, got %s",r.Verdict) }; found:=false; for _,f:=range r.Findings { if f.ID=="NS-NET-002" { found=true } }; if !found { t.Fatalf("expected NS-NET-002, got %#v",r.Findings) } }
func TestScanWarnsWhenEffectiveUserIsUnverified(t *testing.T) { m:=safeManifest("named-user"); m.UserIdentityVerified=false; r:=Scan(m); if r.Verdict!=VerdictWarn { t.Fatalf("expected warn, got %s",r.Verdict) }; found:=false; for _,f:=range r.Findings { if f.ID=="NS-ISO-006" { found=true } }; if !found { t.Fatalf("expected NS-ISO-006") } }
func TestSHAValidationAcceptsUpperHex(t *testing.T) { if !validSHA256(strings.Repeat("A",64)) { t.Fatal("expected uppercase SHA") } }
