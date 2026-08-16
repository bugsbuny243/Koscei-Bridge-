//go:build linux && nodeshield_integration

package nodeshield

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type integrationManifest struct { Schema string `json:"schema"`; Objects []BPFObjectManifest `json:"objects"` }
type procExecutableVerifier struct{ pid int }

func (v procExecutableVerifier) VerifyWorkloadIdentity(_ context.Context,cfg BPFLoadConfig)error{
	membership,err:=os.ReadFile(fmt.Sprintf("/proc/%d/cgroup",v.pid));if err!=nil{return err};rel,err:=filepath.Rel("/sys/fs/cgroup",cfg.CgroupPath);if err!=nil{return err};rel="/"+strings.TrimPrefix(filepath.ToSlash(rel),"/");found:=false
	for _,line:=range strings.Split(string(membership),"\n"){parts:=strings.SplitN(line,":",3);if len(parts)!=3||parts[0]!="0"{continue};got:=strings.TrimSpace(parts[2]);if got==rel||strings.HasPrefix(got,strings.TrimSuffix(rel,"/")+"/"){found=true;break}}
	if !found{return fmt.Errorf("pid %d is not in protected cgroup subtree",v.pid)}
	exePath,err:=os.Readlink(fmt.Sprintf("/proc/%d/exe",v.pid));if err!=nil{return err};data,err:=os.ReadFile(exePath);if err!=nil{return err};sum:=sha256.Sum256(data);if hex.EncodeToString(sum[:])!=strings.ToLower(cfg.ArtifactSHA256){return fmt.Errorf("helper executable digest does not match approved artifact")};return nil
}

func TestNodeShieldKernelHelper(t *testing.T){
	if os.Getenv("NODESHIELD_KERNEL_HELPER")!="1"{t.Skip("helper only")}
	prePath:=os.Getenv("NODESHIELD_PREOPEN_PATH");createPath:=os.Getenv("NODESHIELD_CREATE_PATH");truncatePath:=os.Getenv("NODESHIELD_TRUNCATE_PATH")
	pre,err:=os.OpenFile(prePath,os.O_CREATE|os.O_WRONLY,0o600);if err!=nil{t.Fatal(err)};defer pre.Close()
	// Open a raw socket before the parent freezes and arms policy. The later
	// send must still be denied, proving pre-opened raw descriptors cannot escape.
	rawFD,err:=unix.Socket(unix.AF_INET,unix.SOCK_RAW,unix.IPPROTO_RAW);if err!=nil{t.Fatalf("pre-open raw socket: %v",err)};defer unix.Close(rawFD)
	reader:=bufio.NewReader(os.Stdin);fmt.Fprintln(os.Stdout,"READY");if _,err:=reader.ReadString('\n');err!=nil{t.Fatal(err)}

	for _,tc:=range []struct{network,addr string}{{"tcp4",os.Getenv("NODESHIELD_ALLOWED4_ADDR")},{"tcp6",os.Getenv("NODESHIELD_ALLOWED6_ADDR")}}{c,err:=net.DialTimeout(tc.network,tc.addr,2*time.Second);if err!=nil{t.Fatalf("allowed %s blocked: %v",tc.network,err)};_=c.Close()}
	for _,tc:=range []struct{network,addr string}{{"tcp4",os.Getenv("NODESHIELD_DENIED4_ADDR")},{"tcp6",os.Getenv("NODESHIELD_DENIED6_ADDR")}}{if c,err:=net.DialTimeout(tc.network,tc.addr,2*time.Second);err==nil{_=c.Close();t.Fatalf("denied %s succeeded",tc.network)}}
	for _,tc:=range []struct{network,addr string}{{"udp4",os.Getenv("NODESHIELD_ALLOWED_UDP4")},{"udp6",os.Getenv("NODESHIELD_ALLOWED_UDP6")}}{addr,err:=net.ResolveUDPAddr(tc.network,tc.addr);if err!=nil{t.Fatal(err)};c,err:=net.ListenUDP(tc.network,nil);if err!=nil{t.Fatal(err)};_,err=c.WriteToUDP([]byte("ok"),addr);_=c.Close();if err!=nil{t.Fatalf("allowed %s sendmsg blocked: %v",tc.network,err)}}
	for _,tc:=range []struct{network,addr string}{{"udp4",os.Getenv("NODESHIELD_DENIED_UDP4")},{"udp6",os.Getenv("NODESHIELD_DENIED_UDP6")}}{addr,err:=net.ResolveUDPAddr(tc.network,tc.addr);if err!=nil{t.Fatal(err)};c,err:=net.ListenUDP(tc.network,nil);if err!=nil{t.Fatal(err)};_,sendErr:=c.WriteToUDP([]byte("no"),addr);_=c.Close();if sendErr==nil{t.Fatalf("denied %s sendmsg succeeded",tc.network)}}
	if fd,err:=unix.Socket(unix.AF_INET,unix.SOCK_RAW,unix.IPPROTO_RAW);err==nil{_=unix.Close(fd);t.Fatal("raw socket creation succeeded after policy arm")}else if err!=unix.EPERM{t.Fatalf("raw socket creation expected EPERM, got %v",err)}
	packet:=make([]byte,20);packet[0]=0x45;packet[2]=0;packet[3]=20;packet[8]=64;packet[9]=unix.IPPROTO_ICMP;packet[12]=127;packet[15]=1;packet[16]=127;packet[19]=1
	if err:=unix.Sendto(rawFD,packet,0,&unix.SockaddrInet4{Addr:[4]byte{127,0,0,1}});err!=unix.EPERM{t.Fatalf("pre-opened raw socket send expected EPERM, got %v",err)}

	if _,err:=pre.Write([]byte("no"));err==nil{t.Fatal("pre-opened fd write succeeded")}
	if err:=os.WriteFile(createPath,[]byte("no"),0o600);err==nil{t.Fatal("forbidden create succeeded")};if _,err:=os.Stat(createPath);!os.IsNotExist(err){t.Fatalf("denied create left side effect: %v",err)}
	if f,err:=os.OpenFile(truncatePath,os.O_WRONLY|os.O_TRUNC,0);err==nil{_=f.Close();t.Fatal("forbidden truncate succeeded")};content,err:=os.ReadFile(truncatePath);if err!=nil{t.Fatal(err)};if string(content)!="ORIGINAL"{t.Fatalf("denied truncate changed content: %q",content)}
	if err:=syscall.Setuid(65534);err==nil{t.Fatal("setuid succeeded")};if err:=syscall.Setgid(65534);err==nil{t.Fatal("setgid succeeded")};if err:=syscall.Setgroups([]int{65534});err==nil{t.Fatal("setgroups succeeded")}
	h:=&unix.CapUserHeader{Version:unix.LINUX_CAPABILITY_VERSION_3,Pid:0};d:=&unix.CapUserData{};if err:=unix.Capget(h,d);err!=nil{t.Fatal(err)};if err:=unix.Capset(h,&unix.CapUserData{});err==nil{t.Fatal("capset succeeded")}
	if err:=syscall.Exec("/bin/true",[]string{"true"},os.Environ());err==nil{t.Fatal("exec succeeded")};fmt.Fprintln(os.Stdout,"ENFORCEMENT_OK")
}

func TestLinuxCOREBackendKernelEnforcement(t *testing.T){
	if os.Geteuid()!=0{t.Fatal("privileged root runner is required")};mp:=os.Getenv("NODESHIELD_BPF_MANIFEST");if mp==""{t.Fatal("manifest required")};mb,err:=os.ReadFile(mp);if err!=nil{t.Fatal(err)};var manifest integrationManifest;if err:=json.Unmarshal(mb,&manifest);err!=nil{t.Fatal(err)}
	listenTCP:=func(network,address string)net.Listener{l,e:=net.Listen(network,address);if e!=nil{t.Fatal(e)};return l};a4:=listenTCP("tcp4","127.0.0.1:0");defer a4.Close();d4:=listenTCP("tcp4","127.0.0.1:0");defer d4.Close();a6:=listenTCP("tcp6","[::1]:0");defer a6.Close();d6:=listenTCP("tcp6","[::1]:0");defer d6.Close();for _,l:=range []net.Listener{a4,d4,a6,d6}{go drainOne(l)}
	listenUDP:=func(network,address string)*net.UDPConn{a,e:=net.ResolveUDPAddr(network,address);if e!=nil{t.Fatal(e)};c,e:=net.ListenUDP(network,a);if e!=nil{t.Fatal(e)};return c};u4:=listenUDP("udp4","127.0.0.1:0");defer u4.Close();du4:=listenUDP("udp4","127.0.0.1:0");defer du4.Close();u6:=listenUDP("udp6","[::1]:0");defer u6.Close();du6:=listenUDP("udp6","[::1]:0");defer du6.Close()
	a4ap,_:=netip.ParseAddrPort(a4.Addr().String());a6ap,_:=netip.ParseAddrPort(a6.Addr().String());u4ap,_:=netip.ParseAddrPort(u4.LocalAddr().String());u6ap,_:=netip.ParseAddrPort(u6.LocalAddr().String())
	cg:=filepath.Join("/sys/fs/cgroup",fmt.Sprintf("koschei-nodeshield-it-%d",os.Getpid()));child:=filepath.Join(cg,"child");if err:=os.Mkdir(cg,0o755);err!=nil{t.Fatal(err)};defer os.RemoveAll(cg);if err:=os.Mkdir(child,0o755);err!=nil{t.Fatal(err)};info,_:=os.Stat(cg);st:=info.Sys().(*syscall.Stat_t)
	exe,_:=os.Executable();eb,_:=os.ReadFile(exe);sum:=sha256.Sum256(eb);artifact:=hex.EncodeToString(sum[:]);tmp:=t.TempDir();pre:=filepath.Join(tmp,"pre");create:=filepath.Join(tmp,"create");truncate:=filepath.Join(tmp,"truncate");if err:=os.WriteFile(truncate,[]byte("ORIGINAL"),0o600);err!=nil{t.Fatal(err)}
	cmd:=exec.Command(exe,"-test.run=^TestNodeShieldKernelHelper$");cmd.Env=append(os.Environ(),"NODESHIELD_KERNEL_HELPER=1","NODESHIELD_ALLOWED4_ADDR="+a4.Addr().String(),"NODESHIELD_DENIED4_ADDR="+d4.Addr().String(),"NODESHIELD_ALLOWED6_ADDR="+a6.Addr().String(),"NODESHIELD_DENIED6_ADDR="+d6.Addr().String(),"NODESHIELD_ALLOWED_UDP4="+u4.LocalAddr().String(),"NODESHIELD_DENIED_UDP4="+du4.LocalAddr().String(),"NODESHIELD_ALLOWED_UDP6="+u6.LocalAddr().String(),"NODESHIELD_DENIED_UDP6="+du6.LocalAddr().String(),"NODESHIELD_PREOPEN_PATH="+pre,"NODESHIELD_CREATE_PATH="+create,"NODESHIELD_TRUNCATE_PATH="+truncate);stdin,_:=cmd.StdinPipe();stdout,_:=cmd.StdoutPipe();cmd.Stderr=os.Stderr;if err:=cmd.Start();err!=nil{t.Fatal(err)};defer func(){if cmd.Process!=nil{_=cmd.Process.Kill()}}();scanner:=bufio.NewScanner(stdout);if !scanner.Scan()||scanner.Text()!="READY"{t.Fatal("helper not ready")};if err:=os.WriteFile(filepath.Join(child,"cgroup.procs"),[]byte(strconv.Itoa(cmd.Process.Pid)),0o644);err!=nil{t.Fatal(err)}
	cfg:=BPFLoadConfig{WorkloadID:"kernel-integration",CgroupPath:cg,CgroupID:st.Ino,ArtifactSHA256:artifact,DenyExec:true,DenyFileWrite:true,DenyPrivilege:true,AllowedIPs:[]BPFEndpoint{{Address:a4ap.Addr(),Port:a4ap.Port()},{Address:a6ap.Addr(),Port:a6ap.Port()},{Address:u4ap.Addr(),Port:u4ap.Port()},{Address:u6ap.Addr(),Port:u6ap.Port()}}};backend:=NewLinuxCOREBackend(procExecutableVerifier{pid:cmd.Process.Pid});defer backend.Close();result,err:=LoadVerifiedBPF(context.Background(),backend,cfg,manifest.Objects);if err!=nil{t.Fatal(err)};if !result.SubtreeScoped||!result.DualStack||!result.FileIOCovered||!result.CredentialCovered||!result.RawSocketCovered||!result.FrozenDuringArm||!result.AtomicCgroupHandle{t.Fatalf("coverage incomplete: %#v",result)}
	if _,err:=io.WriteString(stdin,"go\n");err!=nil{t.Fatal(err)};_=stdin.Close();if !scanner.Scan()||scanner.Text()!="ENFORCEMENT_OK"{t.Fatalf("proof failed: %q",scanner.Text())};if err:=cmd.Wait();err!=nil{t.Fatal(err)};cmd.Process=nil
}

func drainOne(l net.Listener){c,err:=l.Accept();if err==nil{_=c.Close()}}
