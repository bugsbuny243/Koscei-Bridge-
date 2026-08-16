package nodeshield

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

type fakeBPFBackend struct { result BPFLoadResult; err error }
func (f fakeBPFBackend) LoadAndAttach(_ context.Context, _ BPFLoadConfig, _ []VerifiedBPFObject) (BPFLoadResult, error) { return f.result, f.err }

func testBPFManifest(t *testing.T) BPFObjectManifest { t.Helper(); path:=filepath.Join(t.TempDir(),"program.o");data:=[]byte("object");if err:=os.WriteFile(path,data,0o600);err!=nil{t.Fatal(err)};sum:=sha256.Sum256(data);return BPFObjectManifest{Name:"test",Path:path,SHA256:hex.EncodeToString(sum[:])} }
func testBPFLoadConfig() BPFLoadConfig { return BPFLoadConfig{WorkloadID:"w1",CgroupPath:"/sys/fs/cgroup/koschei/w1",CgroupID:42,ArtifactSHA256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",DenyExec:true,DenyFileWrite:true,DenyPrivilege:true,AllowedIPs:[]BPFEndpoint{{Address:netip.MustParseAddr("1.1.1.1"),Port:443},{Address:netip.MustParseAddr("2001:db8::1"),Port:443}}} }
func completeBPFResult() BPFLoadResult { return BPFLoadResult{LSMAttached:true,ConnectAttached:true,PolicyMapsReady:true,ArtifactBound:true,SubtreeScoped:true,DualStack:true,FileIOCovered:true,CredentialCovered:true,RawSocketCovered:true,FrozenDuringArm:true,AtomicCgroupHandle:true} }

func TestLoadVerifiedBPFRequiresCompleteAttachmentState(t *testing.T){r:=completeBPFResult();r.PolicyMapsReady=false;if _,err:=LoadVerifiedBPF(context.Background(),fakeBPFBackend{result:r},testBPFLoadConfig(),[]BPFObjectManifest{testBPFManifest(t)});err==nil{t.Fatal("expected incomplete policy map state to fail closed")}}
func TestLoadVerifiedBPFRejectsMissingCoverageEvidence(t *testing.T){r:=completeBPFResult();r.DualStack=false;if _,err:=LoadVerifiedBPF(context.Background(),fakeBPFBackend{result:r},testBPFLoadConfig(),[]BPFObjectManifest{testBPFManifest(t)});err==nil{t.Fatal("expected missing dual-stack evidence to fail closed")};r=completeBPFResult();r.RawSocketCovered=false;if _,err:=LoadVerifiedBPF(context.Background(),fakeBPFBackend{result:r},testBPFLoadConfig(),[]BPFObjectManifest{testBPFManifest(t)});err==nil{t.Fatal("expected missing raw-socket evidence to fail closed")}}
func TestLoadVerifiedBPFAcceptsCompleteState(t *testing.T){result,err:=LoadVerifiedBPF(context.Background(),fakeBPFBackend{result:completeBPFResult()},testBPFLoadConfig(),[]BPFObjectManifest{testBPFManifest(t)});if err!=nil{t.Fatalf("expected complete BPF state: %v",err)};if !result.ObjectsVerified{t.Fatal("expected object verification to be recorded")}}
func TestBPFLoadConfigAcceptsIPv4AndIPv6(t *testing.T){cfg:=testBPFLoadConfig();if err:=cfg.Validate();err!=nil{t.Fatalf("expected dual-stack endpoints: %v",err)};cfg.AllowedIPs=[]BPFEndpoint{{Address:netip.Addr{},Port:443}};if err:=cfg.Validate();err==nil{t.Fatal("expected invalid endpoint to be rejected")}}
