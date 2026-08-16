//go:build linux

package nodeshield

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type linuxWorkloadGate struct { Enabled, DenyExec, DenyFileWrite, DenyPrivilege, DenyRawSocket uint8 }
type linuxArtifactDigest struct{ SHA256 [32]byte }
type linuxEndpoint4 struct { Addr uint32; Port uint16; Pad uint16 }
type linuxEndpoint6 struct { Addr [4]uint32; Port uint16; Pad uint16 }

type linuxLSMObjects struct {
	BprmCheck *ebpf.Program `ebpf:"nodeshield_bprm_check"`
	FilePermission *ebpf.Program `ebpf:"nodeshield_file_permission"`
	InodeCreate *ebpf.Program `ebpf:"nodeshield_inode_create"`
	InodePermission *ebpf.Program `ebpf:"nodeshield_inode_permission"`
	InodeSetattr *ebpf.Program `ebpf:"nodeshield_inode_setattr"`
	TaskFixSetuid *ebpf.Program `ebpf:"nodeshield_task_fix_setuid"`
	TaskFixSetgid *ebpf.Program `ebpf:"nodeshield_task_fix_setgid"`
	TaskFixSetgroups *ebpf.Program `ebpf:"nodeshield_task_fix_setgroups"`
	Capset *ebpf.Program `ebpf:"nodeshield_capset"`
	SocketCreate *ebpf.Program `ebpf:"nodeshield_socket_create"`
	SocketSendmsg *ebpf.Program `ebpf:"nodeshield_socket_sendmsg"`
	WorkloadGate *ebpf.Map `ebpf:"workload_gate_map"`
	ArtifactBinding *ebpf.Map `ebpf:"artifact_binding_map"`
}

func (o *linuxLSMObjects) Close() {
	for _,p:=range []*ebpf.Program{o.BprmCheck,o.FilePermission,o.InodeCreate,o.InodePermission,o.InodeSetattr,o.TaskFixSetuid,o.TaskFixSetgid,o.TaskFixSetgroups,o.Capset,o.SocketCreate,o.SocketSendmsg} { if p!=nil { _=p.Close() } }
	if o.WorkloadGate!=nil { _=o.WorkloadGate.Close() }; if o.ArtifactBinding!=nil { _=o.ArtifactBinding.Close() }
}

type linuxConnectObjects struct {
	Connect4 *ebpf.Program `ebpf:"nodeshield_connect4"`
	Connect6 *ebpf.Program `ebpf:"nodeshield_connect6"`
	Sendmsg4 *ebpf.Program `ebpf:"nodeshield_sendmsg4"`
	Sendmsg6 *ebpf.Program `ebpf:"nodeshield_sendmsg6"`
	NetworkGate *ebpf.Map `ebpf:"network_gate"`
	AllowedEndpoints4 *ebpf.Map `ebpf:"allowed_endpoints4"`
	AllowedEndpoints6 *ebpf.Map `ebpf:"allowed_endpoints6"`
}
func (o *linuxConnectObjects) Close() { for _,p:=range []*ebpf.Program{o.Connect4,o.Connect6,o.Sendmsg4,o.Sendmsg6} { if p!=nil { _=p.Close() } }; if o.NetworkGate!=nil {_=o.NetworkGate.Close()}; if o.AllowedEndpoints4!=nil {_=o.AllowedEndpoints4.Close()}; if o.AllowedEndpoints6!=nil {_=o.AllowedEndpoints6.Close()} }

type linuxBPFSession struct { lsm linuxLSMObjects; connect linuxConnectObjects; links []link.Link }
func (s *linuxBPFSession) Close(){ for i:=len(s.links)-1;i>=0;i--{_=s.links[i].Close()}; s.connect.Close(); s.lsm.Close() }

type LinuxCOREBackend struct { mu sync.Mutex; sessions map[string]*linuxBPFSession; identityVerifier WorkloadIdentityVerifier; closed bool }
func NewLinuxCOREBackend(v WorkloadIdentityVerifier)*LinuxCOREBackend{ return &LinuxCOREBackend{sessions:make(map[string]*linuxBPFSession),identityVerifier:v} }

func (b *LinuxCOREBackend) LoadAndAttach(ctx context.Context,cfg BPFLoadConfig,objects []VerifiedBPFObject)(BPFLoadResult,error){
	b.mu.Lock(); defer b.mu.Unlock()
	if b.closed{return BPFLoadResult{},fmt.Errorf("linux CO-RE backend is closed")}; if err:=ctx.Err();err!=nil{return BPFLoadResult{},err}; if err:=cfg.Validate();err!=nil{return BPFLoadResult{},err}
	cg,err:=openVerifiedCgroup(cfg.CgroupPath,cfg.CgroupID); if err!=nil{return BPFLoadResult{},err}; defer cg.Close()
	frozen:=false; if err:=setCgroupFrozen(cg,true);err!=nil{return BPFLoadResult{},fmt.Errorf("freeze workload cgroup: %w",err)}; frozen=true; defer func(){if frozen{_=setCgroupFrozen(cg,false)}}()
	if err:=RequireVerifiedWorkloadIdentity(ctx,b.identityVerifier,cfg);err!=nil{return BPFLoadResult{},err}
	lsmBytes,connBytes,err:=nodeShieldObjectBytes(objects); if err!=nil{return BPFLoadResult{},err}
	var s linuxBPFSession; cleanup:=true; defer func(){if cleanup{s.Close()}}()
	lsmSpec,err:=ebpf.LoadCollectionSpecFromReader(bytes.NewReader(lsmBytes)); if err!=nil{return BPFLoadResult{},fmt.Errorf("parse verified LSM object: %w",err)}; if err:=normalizeCgroupLSMSpec(lsmSpec);err!=nil{return BPFLoadResult{},fmt.Errorf("normalize cgroup LSM spec: %w",err)}; if err:=lsmSpec.LoadAndAssign(&s.lsm,nil);err!=nil{return BPFLoadResult{},fmt.Errorf("load LSM objects: %w",err)}
	connSpec,err:=ebpf.LoadCollectionSpecFromReader(bytes.NewReader(connBytes)); if err!=nil{return BPFLoadResult{},fmt.Errorf("parse verified connect object: %w",err)}; if err:=connSpec.LoadAndAssign(&s.connect,nil);err!=nil{return BPFLoadResult{},fmt.Errorf("load connect objects: %w",err)}
	zero:=uint32(0); if err:=s.lsm.WorkloadGate.Update(zero,linuxWorkloadGate{},ebpf.UpdateAny);err!=nil{return BPFLoadResult{},err}; if err:=s.connect.NetworkGate.Update(zero,uint8(0),ebpf.UpdateAny);err!=nil{return BPFLoadResult{},err}
	ab,err:=hex.DecodeString(cfg.ArtifactSHA256); if err!=nil||len(ab)!=sha256.Size{return BPFLoadResult{},fmt.Errorf("decode artifact sha256")}; var digest linuxArtifactDigest; copy(digest.SHA256[:],ab); if err:=s.lsm.ArtifactBinding.Update(zero,digest,ebpf.UpdateAny);err!=nil{return BPFLoadResult{},err}; var vd linuxArtifactDigest; if err:=s.lsm.ArtifactBinding.Lookup(zero,&vd);err!=nil||vd!=digest{return BPFLoadResult{},fmt.Errorf("verify artifact digest binding")}
	one:=uint8(1); for _,ep:=range cfg.AllowedIPs{ if ep.Address.Is4(){a:=ep.Address.As4();key:=linuxEndpoint4{Addr:binary.BigEndian.Uint32(a[:]),Port:ep.Port};if err:=s.connect.AllowedEndpoints4.Update(key,one,ebpf.UpdateAny);err!=nil{return BPFLoadResult{},err}}else{a:=ep.Address.As16();key:=linuxEndpoint6{Port:ep.Port};for i:=0;i<4;i++{key.Addr[i]=binary.BigEndian.Uint32(a[i*4:(i+1)*4])};if err:=s.connect.AllowedEndpoints6.Update(key,one,ebpf.UpdateAny);err!=nil{return BPFLoadResult{},err}} }
	for _,prog:=range []*ebpf.Program{s.lsm.BprmCheck,s.lsm.FilePermission,s.lsm.InodeCreate,s.lsm.InodePermission,s.lsm.InodeSetattr,s.lsm.TaskFixSetuid,s.lsm.TaskFixSetgid,s.lsm.TaskFixSetgroups,s.lsm.Capset,s.lsm.SocketCreate,s.lsm.SocketSendmsg}{lnk,err:=link.AttachRawLink(link.RawLinkOptions{Target:int(cg.Fd()),Program:prog,Attach:ebpf.AttachLSMCgroup});if err!=nil{return BPFLoadResult{},fmt.Errorf("attach cgroup LSM: %w",err)};if _,err:=lnk.Info();err!=nil{_=lnk.Close();return BPFLoadResult{},err};s.links=append(s.links,lnk)}
	for _,it:=range []struct{p *ebpf.Program;a ebpf.AttachType;n string}{{s.connect.Connect4,ebpf.AttachCGroupInet4Connect,"connect4"},{s.connect.Connect6,ebpf.AttachCGroupInet6Connect,"connect6"},{s.connect.Sendmsg4,ebpf.AttachCGroupUDP4Sendmsg,"sendmsg4"},{s.connect.Sendmsg6,ebpf.AttachCGroupUDP6Sendmsg,"sendmsg6"}}{lnk,err:=link.AttachRawLink(link.RawLinkOptions{Target:int(cg.Fd()),Program:it.p,Attach:it.a});if err!=nil{return BPFLoadResult{},fmt.Errorf("attach cgroup %s: %w",it.n,err)};if _,err:=lnk.Info();err!=nil{_=lnk.Close();return BPFLoadResult{},err};s.links=append(s.links,lnk)}
	gate:=linuxWorkloadGate{Enabled:1,DenyExec:boolByte(cfg.DenyExec),DenyFileWrite:boolByte(cfg.DenyFileWrite),DenyPrivilege:boolByte(cfg.DenyPrivilege),DenyRawSocket:1}; if err:=s.lsm.WorkloadGate.Update(zero,gate,ebpf.UpdateAny);err!=nil{return BPFLoadResult{},err}; if err:=s.connect.NetworkGate.Update(zero,one,ebpf.UpdateAny);err!=nil{return BPFLoadResult{},err}
	if err:=setCgroupFrozen(cg,false);err!=nil{return BPFLoadResult{},fmt.Errorf("unfreeze protected workload: %w",err)}; frozen=false
	if old:=b.sessions[cfg.WorkloadID];old!=nil{old.Close()};b.sessions[cfg.WorkloadID]=&s;cleanup=false
	return BPFLoadResult{LSMAttached:true,ConnectAttached:true,PolicyMapsReady:true,ArtifactBound:true,SubtreeScoped:true,DualStack:true,FileIOCovered:true,CredentialCovered:true,RawSocketCovered:true,FrozenDuringArm:true,AtomicCgroupHandle:true},nil
}

func (b *LinuxCOREBackend) CloseWorkload(id string)error{b.mu.Lock();defer b.mu.Unlock();s:=b.sessions[id];if s==nil{return nil};delete(b.sessions,id);s.Close();return nil}
func (b *LinuxCOREBackend) Close()error{b.mu.Lock();defer b.mu.Unlock();if b.closed{return nil};b.closed=true;for id,s:=range b.sessions{s.Close();delete(b.sessions,id)};return nil}

func openVerifiedCgroup(path string,expected uint64)(*os.File,error){fd,err:=unix.Open(path,unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,0);if err!=nil{return nil,fmt.Errorf("open cgroup path: %w",err)};f:=os.NewFile(uintptr(fd),path);if f==nil{_=unix.Close(fd);return nil,fmt.Errorf("wrap cgroup fd")};var st unix.Stat_t;if err:=unix.Fstat(fd,&st);err!=nil{f.Close();return nil,err};if st.Ino!=expected{f.Close();return nil,fmt.Errorf("cgroup identity mismatch: fd inode=%d expected=%d",st.Ino,expected)};return f,nil}
func setCgroupFrozen(cg *os.File,frozen bool)error{v:=[]byte("0");if frozen{v=[]byte("1")};fd,err:=unix.Openat(int(cg.Fd()),"cgroup.freeze",unix.O_WRONLY|unix.O_CLOEXEC,0);if err!=nil{return err};if _,err:=unix.Write(fd,v);err!=nil{_=unix.Close(fd);return err};if err:=unix.Close(fd);err!=nil{return err};deadline:=time.Now().Add(3*time.Second);want:="frozen 0";if frozen{want="frozen 1"};for{if time.Now().After(deadline){return fmt.Errorf("timed out waiting for %s",want)};efd,err:=unix.Openat(int(cg.Fd()),"cgroup.events",unix.O_RDONLY|unix.O_CLOEXEC,0);if err!=nil{return err};buf:=make([]byte,4096);n,rerr:=unix.Read(efd,buf);_=unix.Close(efd);if rerr!=nil{return rerr};if strings.Contains(string(buf[:n]),want){return nil};time.Sleep(10*time.Millisecond)}}
func nodeShieldObjectBytes(objects []VerifiedBPFObject)([]byte,[]byte,error){var l,c []byte;for _,o:=range objects{switch o.Name{case"nodeshield_lsm":l=o.Bytes;case"nodeshield_connect":c=o.Bytes}};if len(l)==0||len(c)==0{return nil,nil,fmt.Errorf("verified BPF objects must contain nodeshield_lsm and nodeshield_connect")};return l,c,nil}
func boolByte(v bool)uint8{if v{return 1};return 0}
