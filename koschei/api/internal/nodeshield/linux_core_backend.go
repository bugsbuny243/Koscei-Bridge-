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

type linuxWorkloadGate struct {
	Enabled       uint8
	DenyExec      uint8
	DenyFileWrite uint8
	DenyPrivilege uint8
}

type linuxArtifactDigest struct{ SHA256 [32]byte }

type linuxEndpoint4 struct {
	Addr uint32
	Port uint16
	Pad  uint16
}

type linuxEndpoint6 struct {
	Addr [4]uint32
	Port uint16
	Pad  uint16
}

type linuxLSMObjects struct {
	BprmCheck         *ebpf.Program `ebpf:"nodeshield_bprm_check"`
	FilePermission    *ebpf.Program `ebpf:"nodeshield_file_permission"`
	TaskFixSetuid     *ebpf.Program `ebpf:"nodeshield_task_fix_setuid"`
	TaskFixSetgid     *ebpf.Program `ebpf:"nodeshield_task_fix_setgid"`
	TaskFixSetgroups  *ebpf.Program `ebpf:"nodeshield_task_fix_setgroups"`
	Capset            *ebpf.Program `ebpf:"nodeshield_capset"`
	WorkloadGate      *ebpf.Map     `ebpf:"workload_gate_map"`
	ArtifactBinding   *ebpf.Map     `ebpf:"artifact_binding_map"`
}

func (o *linuxLSMObjects) Close() {
	for _, p := range []*ebpf.Program{o.BprmCheck, o.FilePermission, o.TaskFixSetuid, o.TaskFixSetgid, o.TaskFixSetgroups, o.Capset} {
		if p != nil { _ = p.Close() }
	}
	if o.WorkloadGate != nil { _ = o.WorkloadGate.Close() }
	if o.ArtifactBinding != nil { _ = o.ArtifactBinding.Close() }
}

type linuxConnectObjects struct {
	Connect4          *ebpf.Program `ebpf:"nodeshield_connect4"`
	Connect6          *ebpf.Program `ebpf:"nodeshield_connect6"`
	NetworkGate       *ebpf.Map     `ebpf:"network_gate"`
	AllowedEndpoints4 *ebpf.Map     `ebpf:"allowed_endpoints4"`
	AllowedEndpoints6 *ebpf.Map     `ebpf:"allowed_endpoints6"`
}

func (o *linuxConnectObjects) Close() {
	for _, p := range []*ebpf.Program{o.Connect4, o.Connect6} {
		if p != nil { _ = p.Close() }
	}
	if o.NetworkGate != nil { _ = o.NetworkGate.Close() }
	if o.AllowedEndpoints4 != nil { _ = o.AllowedEndpoints4.Close() }
	if o.AllowedEndpoints6 != nil { _ = o.AllowedEndpoints6.Close() }
}

type linuxBPFSession struct {
	lsm     linuxLSMObjects
	connect linuxConnectObjects
	links   []link.Link
}

func (s *linuxBPFSession) Close() {
	for i := len(s.links) - 1; i >= 0; i-- { _ = s.links[i].Close() }
	s.connect.Close()
	s.lsm.Close()
}

// LinuxCOREBackend serializes privileged load/close operations so shutdown
// cannot race a partially installed session.
type LinuxCOREBackend struct {
	mu               sync.Mutex
	sessions         map[string]*linuxBPFSession
	identityVerifier WorkloadIdentityVerifier
	closed           bool
}

func NewLinuxCOREBackend(identityVerifier WorkloadIdentityVerifier) *LinuxCOREBackend {
	return &LinuxCOREBackend{sessions: make(map[string]*linuxBPFSession), identityVerifier: identityVerifier}
}

func (b *LinuxCOREBackend) LoadAndAttach(ctx context.Context, cfg BPFLoadConfig, objects []VerifiedBPFObject) (BPFLoadResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed { return BPFLoadResult{}, fmt.Errorf("linux CO-RE backend is closed") }
	if err := ctx.Err(); err != nil { return BPFLoadResult{}, err }
	if err := cfg.Validate(); err != nil { return BPFLoadResult{}, err }

	cgroupFile, err := openVerifiedCgroup(cfg.CgroupPath, cfg.CgroupID)
	if err != nil { return BPFLoadResult{}, err }
	defer cgroupFile.Close()

	frozen := false
	if err := setCgroupFrozen(cgroupFile, true); err != nil { return BPFLoadResult{}, fmt.Errorf("freeze workload cgroup: %w", err) }
	frozen = true
	defer func() { if frozen { _ = setCgroupFrozen(cgroupFile, false) } }()

	if err := RequireVerifiedWorkloadIdentity(ctx, b.identityVerifier, cfg); err != nil { return BPFLoadResult{}, err }
	lsmBytes, connectBytes, err := nodeShieldObjectBytes(objects)
	if err != nil { return BPFLoadResult{}, err }

	var session linuxBPFSession
	cleanup := true
	defer func() { if cleanup { session.Close() } }()

	lsmSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(lsmBytes))
	if err != nil { return BPFLoadResult{}, fmt.Errorf("parse verified LSM object: %w", err) }
	if err := lsmSpec.LoadAndAssign(&session.lsm, nil); err != nil { return BPFLoadResult{}, fmt.Errorf("load LSM objects: %w", err) }
	connectSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(connectBytes))
	if err != nil { return BPFLoadResult{}, fmt.Errorf("parse verified connect object: %w", err) }
	if err := connectSpec.LoadAndAssign(&session.connect, nil); err != nil { return BPFLoadResult{}, fmt.Errorf("load connect objects: %w", err) }

	zero := uint32(0)
	if err := session.lsm.WorkloadGate.Update(zero, linuxWorkloadGate{}, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("initialize disabled workload gate: %w", err) }
	if err := session.connect.NetworkGate.Update(zero, uint8(0), ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("initialize disabled network gate: %w", err) }

	artifactBytes, err := hex.DecodeString(cfg.ArtifactSHA256)
	if err != nil || len(artifactBytes) != sha256.Size { return BPFLoadResult{}, fmt.Errorf("decode artifact sha256") }
	var digest linuxArtifactDigest
	copy(digest.SHA256[:], artifactBytes)
	if err := session.lsm.ArtifactBinding.Update(zero, digest, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("bind artifact digest map: %w", err) }
	var verifiedDigest linuxArtifactDigest
	if err := session.lsm.ArtifactBinding.Lookup(zero, &verifiedDigest); err != nil || verifiedDigest != digest { return BPFLoadResult{}, fmt.Errorf("verify artifact digest binding") }

	one := uint8(1)
	for _, endpoint := range cfg.AllowedIPs {
		if endpoint.Address.Is4() {
			a := endpoint.Address.As4()
			key := linuxEndpoint4{Addr: binary.BigEndian.Uint32(a[:]), Port: endpoint.Port}
			if err := session.connect.AllowedEndpoints4.Update(key, one, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("initialize IPv4 endpoint allowlist: %w", err) }
			continue
		}
		a := endpoint.Address.As16()
		key := linuxEndpoint6{Port: endpoint.Port}
		for i := 0; i < 4; i++ { key.Addr[i] = binary.BigEndian.Uint32(a[i*4 : (i+1)*4]) }
		if err := session.connect.AllowedEndpoints6.Update(key, one, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("initialize IPv6 endpoint allowlist: %w", err) }
	}

	// Attach every program to the SAME verified cgroup FD. BPF_LSM_CGROUP and
	// cgroup socket programs inherit down the subtree, covering child cgroups.
	for _, prog := range []*ebpf.Program{session.lsm.BprmCheck, session.lsm.FilePermission, session.lsm.TaskFixSetuid, session.lsm.TaskFixSetgid, session.lsm.TaskFixSetgroups, session.lsm.Capset} {
		lnk, err := link.AttachRawLink(link.RawLinkOptions{Target: int(cgroupFile.Fd()), Program: prog, Attach: ebpf.AttachLSMCgroup})
		if err != nil { return BPFLoadResult{}, fmt.Errorf("attach cgroup-scoped BPF LSM program: %w", err) }
		if _, err := lnk.Info(); err != nil { _ = lnk.Close(); return BPFLoadResult{}, fmt.Errorf("verify cgroup LSM link: %w", err) }
		session.links = append(session.links, lnk)
	}
	for _, item := range []struct{ prog *ebpf.Program; attach ebpf.AttachType; name string }{
		{session.connect.Connect4, ebpf.AttachCGroupInet4Connect, "connect4"},
		{session.connect.Connect6, ebpf.AttachCGroupInet6Connect, "connect6"},
	} {
		lnk, err := link.AttachRawLink(link.RawLinkOptions{Target: int(cgroupFile.Fd()), Program: item.prog, Attach: item.attach})
		if err != nil { return BPFLoadResult{}, fmt.Errorf("attach cgroup %s program: %w", item.name, err) }
		if _, err := lnk.Info(); err != nil { _ = lnk.Close(); return BPFLoadResult{}, fmt.Errorf("verify cgroup %s link: %w", item.name, err) }
		session.links = append(session.links, lnk)
	}

	gate := linuxWorkloadGate{Enabled: 1, DenyExec: boolByte(cfg.DenyExec), DenyFileWrite: boolByte(cfg.DenyFileWrite), DenyPrivilege: boolByte(cfg.DenyPrivilege)}
	if err := session.lsm.WorkloadGate.Update(zero, gate, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("arm workload gate: %w", err) }
	if err := session.connect.NetworkGate.Update(zero, one, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("arm network gate: %w", err) }

	if err := setCgroupFrozen(cgroupFile, false); err != nil { return BPFLoadResult{}, fmt.Errorf("unfreeze protected workload: %w", err) }
	frozen = false

	if old := b.sessions[cfg.WorkloadID]; old != nil { old.Close() }
	b.sessions[cfg.WorkloadID] = &session
	cleanup = false
	return BPFLoadResult{
		LSMAttached: true, ConnectAttached: true, PolicyMapsReady: true, ArtifactBound: true,
		SubtreeScoped: true, DualStack: true, FileIOCovered: true, CredentialCovered: true,
		FrozenDuringArm: true, AtomicCgroupHandle: true,
	}, nil
}

func (b *LinuxCOREBackend) CloseWorkload(workloadID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[workloadID]
	if s == nil { return nil }
	delete(b.sessions, workloadID)
	s.Close()
	return nil
}

func (b *LinuxCOREBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed { return nil }
	b.closed = true
	for id, s := range b.sessions { s.Close(); delete(b.sessions, id) }
	return nil
}

func openVerifiedCgroup(path string, expected uint64) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil { return nil, fmt.Errorf("open cgroup path: %w", err) }
	f := os.NewFile(uintptr(fd), path)
	if f == nil { _ = unix.Close(fd); return nil, fmt.Errorf("wrap cgroup fd") }
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil { f.Close(); return nil, fmt.Errorf("fstat cgroup: %w", err) }
	if stat.Ino != expected { f.Close(); return nil, fmt.Errorf("cgroup identity mismatch: fd inode=%d expected=%d", stat.Ino, expected) }
	return f, nil
}

func setCgroupFrozen(cgroup *os.File, frozen bool) error {
	value := []byte("0")
	if frozen { value = []byte("1") }
	fd, err := unix.Openat(int(cgroup.Fd()), "cgroup.freeze", unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil { return err }
	if _, err := unix.Write(fd, value); err != nil { _ = unix.Close(fd); return err }
	if err := unix.Close(fd); err != nil { return err }

	deadline := time.Now().Add(3 * time.Second)
	want := "frozen 0"
	if frozen { want = "frozen 1" }
	for {
		if time.Now().After(deadline) { return fmt.Errorf("timed out waiting for %s", want) }
		eventsFD, err := unix.Openat(int(cgroup.Fd()), "cgroup.events", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil { return err }
		buf := make([]byte, 4096)
		n, readErr := unix.Read(eventsFD, buf)
		_ = unix.Close(eventsFD)
		if readErr != nil { return readErr }
		if strings.Contains(string(buf[:n]), want) { return nil }
		time.Sleep(10 * time.Millisecond)
	}
}

func nodeShieldObjectBytes(objects []VerifiedBPFObject) ([]byte, []byte, error) {
	var lsm, connect []byte
	for _, obj := range objects {
		switch obj.Name {
		case "nodeshield_lsm": lsm = obj.Bytes
		case "nodeshield_connect": connect = obj.Bytes
		}
	}
	if len(lsm) == 0 || len(connect) == 0 { return nil, nil, fmt.Errorf("verified BPF objects must contain nodeshield_lsm and nodeshield_connect") }
	return lsm, connect, nil
}

func boolByte(v bool) uint8 { if v { return 1 }; return 0 }
