//go:build linux

package nodeshield

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type linuxWorkloadGate struct {
	Enabled       uint8
	DenyExec      uint8
	DenyFileWrite uint8
	DenyPrivilege uint8
}

type linuxArtifactDigest struct { SHA256 [32]byte }

type linuxEndpoint4 struct {
	Addr uint32
	Port uint16
	Pad  uint16
}

type linuxEndpointKey4 struct {
	CgroupID uint64
	Endpoint linuxEndpoint4
}

type linuxLSMObjects struct {
	BprmCheck       *ebpf.Program `ebpf:"nodeshield_bprm_check"`
	FileOpen        *ebpf.Program `ebpf:"nodeshield_file_open"`
	TaskFixSetuid    *ebpf.Program `ebpf:"nodeshield_task_fix_setuid"`
	WorkloadGates    *ebpf.Map     `ebpf:"workload_gates"`
	ArtifactBindings *ebpf.Map     `ebpf:"artifact_bindings"`
}

func (o *linuxLSMObjects) Close() {
	if o.BprmCheck != nil { _ = o.BprmCheck.Close() }
	if o.FileOpen != nil { _ = o.FileOpen.Close() }
	if o.TaskFixSetuid != nil { _ = o.TaskFixSetuid.Close() }
	if o.WorkloadGates != nil { _ = o.WorkloadGates.Close() }
	if o.ArtifactBindings != nil { _ = o.ArtifactBindings.Close() }
}

type linuxConnectObjects struct {
	Connect4          *ebpf.Program `ebpf:"nodeshield_connect4"`
	ProtectedCgroups  *ebpf.Map     `ebpf:"protected_cgroups"`
	AllowedEndpoints4 *ebpf.Map     `ebpf:"allowed_endpoints4"`
}

func (o *linuxConnectObjects) Close() {
	if o.Connect4 != nil { _ = o.Connect4.Close() }
	if o.ProtectedCgroups != nil { _ = o.ProtectedCgroups.Close() }
	if o.AllowedEndpoints4 != nil { _ = o.AllowedEndpoints4.Close() }
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

// LinuxCOREBackend is the privileged production loader for Node Shield's
// verified CO-RE objects. Attachment handles are retained per workload so a
// successful LoadAndAttach cannot silently detach when the function returns.
type LinuxCOREBackend struct {
	mu       sync.Mutex
	sessions map[string]*linuxBPFSession
}

func NewLinuxCOREBackend() *LinuxCOREBackend {
	return &LinuxCOREBackend{sessions: make(map[string]*linuxBPFSession)}
}

func (b *LinuxCOREBackend) LoadAndAttach(ctx context.Context, cfg BPFLoadConfig, objects []BPFObjectManifest) (BPFLoadResult, error) {
	if err := ctx.Err(); err != nil { return BPFLoadResult{}, err }
	if err := cfg.Validate(); err != nil { return BPFLoadResult{}, err }
	if err := verifyCgroupIdentity(cfg.CgroupPath, cfg.CgroupID); err != nil { return BPFLoadResult{}, err }

	lsmPath, connectPath, err := nodeShieldObjectPaths(objects)
	if err != nil { return BPFLoadResult{}, err }

	var session linuxBPFSession
	cleanup := true
	defer func() { if cleanup { session.Close() } }()

	lsmSpec, err := ebpf.LoadCollectionSpec(lsmPath)
	if err != nil { return BPFLoadResult{}, fmt.Errorf("load LSM collection spec: %w", err) }
	if err := lsmSpec.LoadAndAssign(&session.lsm, nil); err != nil { return BPFLoadResult{}, fmt.Errorf("load LSM objects: %w", err) }

	connectSpec, err := ebpf.LoadCollectionSpec(connectPath)
	if err != nil { return BPFLoadResult{}, fmt.Errorf("load connect collection spec: %w", err) }
	if err := connectSpec.LoadAndAssign(&session.connect, nil); err != nil { return BPFLoadResult{}, fmt.Errorf("load connect objects: %w", err) }

	for _, prog := range []*ebpf.Program{session.lsm.BprmCheck, session.lsm.FileOpen, session.lsm.TaskFixSetuid} {
		lnk, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil { return BPFLoadResult{}, fmt.Errorf("attach BPF LSM program: %w", err) }
		if _, err := lnk.Info(); err != nil {
			_ = lnk.Close()
			return BPFLoadResult{}, fmt.Errorf("verify BPF LSM link: %w", err)
		}
		session.links = append(session.links, lnk)
	}

	connectLink, err := link.AttachCgroup(link.CgroupOptions{Path: cfg.CgroupPath, Attach: ebpf.AttachCGroupInet4Connect, Program: session.connect.Connect4})
	if err != nil { return BPFLoadResult{}, fmt.Errorf("attach cgroup connect4 program: %w", err) }
	if _, err := connectLink.Info(); err != nil {
		_ = connectLink.Close()
		return BPFLoadResult{}, fmt.Errorf("verify cgroup connect4 link: %w", err)
	}
	session.links = append(session.links, connectLink)

	artifactBytes, err := hex.DecodeString(cfg.ArtifactSHA256)
	if err != nil || len(artifactBytes) != sha256.Size { return BPFLoadResult{}, fmt.Errorf("decode artifact sha256") }
	var digest linuxArtifactDigest
	copy(digest.SHA256[:], artifactBytes)
	if err := session.lsm.ArtifactBindings.Update(cfg.CgroupID, digest, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("bind artifact digest map: %w", err) }
	var verifiedDigest linuxArtifactDigest
	if err := session.lsm.ArtifactBindings.Lookup(cfg.CgroupID, &verifiedDigest); err != nil || verifiedDigest != digest { return BPFLoadResult{}, fmt.Errorf("verify artifact digest binding") }

	gate := linuxWorkloadGate{Enabled: 1, DenyExec: boolByte(cfg.DenyExec), DenyFileWrite: boolByte(cfg.DenyFileWrite), DenyPrivilege: boolByte(cfg.DenyPrivilege)}
	if err := session.lsm.WorkloadGates.Update(cfg.CgroupID, gate, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("initialize workload gate map: %w", err) }

	one := uint8(1)
	if err := session.connect.ProtectedCgroups.Update(cfg.CgroupID, one, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("initialize protected cgroup map: %w", err) }
	for _, endpoint := range cfg.AllowedIPv4 {
		addr4 := endpoint.Address.As4()
		key := linuxEndpointKey4{CgroupID: cfg.CgroupID, Endpoint: linuxEndpoint4{Addr: binary.BigEndian.Uint32(addr4[:]), Port: endpoint.Port}}
		if err := session.connect.AllowedEndpoints4.Update(key, one, ebpf.UpdateAny); err != nil { return BPFLoadResult{}, fmt.Errorf("initialize endpoint allowlist: %w", err) }
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if old := b.sessions[cfg.WorkloadID]; old != nil { old.Close() }
	b.sessions[cfg.WorkloadID] = &session
	cleanup = false
	return BPFLoadResult{LSMAttached: true, ConnectAttached: true, PolicyMapsReady: true, ArtifactBound: true}, nil
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
	for id, s := range b.sessions { s.Close(); delete(b.sessions, id) }
	return nil
}

func verifyCgroupIdentity(path string, expected uint64) error {
	info, err := os.Stat(path)
	if err != nil { return fmt.Errorf("stat cgroup path: %w", err) }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok { return fmt.Errorf("read cgroup inode identity") }
	if stat.Ino != expected { return fmt.Errorf("cgroup identity mismatch: path inode=%d expected=%d", stat.Ino, expected) }
	return nil
}

func nodeShieldObjectPaths(objects []BPFObjectManifest) (string, string, error) {
	var lsmPath, connectPath string
	for _, obj := range objects {
		switch obj.Name {
		case "nodeshield_lsm": lsmPath = obj.Path
		case "nodeshield_connect": connectPath = obj.Path
		}
	}
	if lsmPath == "" || connectPath == "" { return "", "", fmt.Errorf("BPF manifest must contain nodeshield_lsm and nodeshield_connect objects") }
	return lsmPath, connectPath, nil
}

func boolByte(v bool) uint8 { if v { return 1 }; return 0 }
