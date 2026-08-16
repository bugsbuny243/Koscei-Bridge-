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

type integrationManifest struct {
	Schema  string              `json:"schema"`
	Objects []BPFObjectManifest `json:"objects"`
}

type procExecutableVerifier struct{ pid int }

func (v procExecutableVerifier) VerifyWorkloadIdentity(_ context.Context, cfg BPFLoadConfig) error {
	membership, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", v.pid))
	if err != nil { return err }
	relExpected, err := filepath.Rel("/sys/fs/cgroup", cfg.CgroupPath)
	if err != nil { return err }
	relExpected = "/" + strings.TrimPrefix(filepath.ToSlash(relExpected), "/")
	found := false
	for _, line := range strings.Split(string(membership), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" { continue }
		got := strings.TrimSpace(parts[2])
		if got == relExpected || strings.HasPrefix(got, strings.TrimSuffix(relExpected, "/")+"/") { found = true; break }
	}
	if !found { return fmt.Errorf("pid %d is not in protected cgroup subtree", v.pid) }

	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", v.pid))
	if err != nil { return err }
	data, err := os.ReadFile(exePath)
	if err != nil { return err }
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(cfg.ArtifactSHA256) {
		return fmt.Errorf("helper executable digest does not match approved artifact")
	}
	return nil
}

func TestNodeShieldKernelHelper(t *testing.T) {
	if os.Getenv("NODESHIELD_KERNEL_HELPER") != "1" { t.Skip("helper only") }
	writePath := os.Getenv("NODESHIELD_WRITE_PATH")
	preopened, err := os.OpenFile(writePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil { t.Fatalf("pre-open proof file: %v", err) }
	defer preopened.Close()

	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintln(os.Stdout, "READY")
	if _, err := reader.ReadString('\n'); err != nil { t.Fatal(err) }

	for _, tc := range []struct{ network, addr string }{
		{"tcp4", os.Getenv("NODESHIELD_ALLOWED4_ADDR")},
		{"tcp6", os.Getenv("NODESHIELD_ALLOWED6_ADDR")},
	} {
		conn, err := net.DialTimeout(tc.network, tc.addr, 2*time.Second)
		if err != nil { t.Fatalf("allowed %s connect was blocked: %v", tc.network, err) }
		_ = conn.Close()
	}
	for _, tc := range []struct{ network, addr string }{
		{"tcp4", os.Getenv("NODESHIELD_DENIED4_ADDR")},
		{"tcp6", os.Getenv("NODESHIELD_DENIED6_ADDR")},
	} {
		if conn, err := net.DialTimeout(tc.network, tc.addr, 2*time.Second); err == nil {
			_ = conn.Close(); t.Fatalf("unauthorized %s connect unexpectedly succeeded", tc.network)
		}
	}

	if _, err := preopened.Write([]byte("must-not-write")); err == nil {
		t.Fatal("write through pre-opened descriptor unexpectedly succeeded")
	}
	if err := os.WriteFile(writePath+".new", []byte("must-not-write"), 0o600); err == nil {
		t.Fatal("new forbidden file write unexpectedly succeeded")
	}
	if err := syscall.Setuid(65534); err == nil { t.Fatal("forbidden setuid unexpectedly succeeded") }
	if err := syscall.Setgid(65534); err == nil { t.Fatal("forbidden setgid unexpectedly succeeded") }
	if err := syscall.Setgroups([]int{65534}); err == nil { t.Fatal("forbidden setgroups unexpectedly succeeded") }

	header := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	data := &unix.CapUserData{}
	if err := unix.Capget(header, data); err != nil { t.Fatalf("capget: %v", err) }
	zeroCaps := &unix.CapUserData{}
	if err := unix.Capset(header, zeroCaps); err == nil { t.Fatal("forbidden capset unexpectedly succeeded") }

	if err := syscall.Exec("/bin/true", []string{"true"}, os.Environ()); err == nil { t.Fatal("forbidden exec unexpectedly succeeded") }
	fmt.Fprintln(os.Stdout, "ENFORCEMENT_OK")
}

func TestLinuxCOREBackendKernelEnforcement(t *testing.T) {
	if os.Geteuid() != 0 { t.Fatal("privileged root runner is required") }
	manifestPath := os.Getenv("NODESHIELD_BPF_MANIFEST")
	if manifestPath == "" { t.Fatal("NODESHIELD_BPF_MANIFEST is required") }
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil { t.Fatal(err) }
	var manifest integrationManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil { t.Fatal(err) }
	if len(manifest.Objects) != 2 { t.Fatalf("expected two BPF objects, got %d", len(manifest.Objects)) }

	allowed4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer allowed4.Close()
	denied4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer denied4.Close()
	allowed6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil { t.Fatalf("IPv6 loopback is required for dual-stack proof: %v", err) }
	defer allowed6.Close()
	denied6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil { t.Fatal(err) }
	defer denied6.Close()
	for _, l := range []net.Listener{allowed4, denied4, allowed6, denied6} { go drainOne(l) }

	allowed4AP, err := netip.ParseAddrPort(allowed4.Addr().String())
	if err != nil { t.Fatal(err) }
	allowed6AP, err := netip.ParseAddrPort(allowed6.Addr().String())
	if err != nil { t.Fatal(err) }

	cgroupPath := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("koschei-nodeshield-it-%d", os.Getpid()))
	childPath := filepath.Join(cgroupPath, "child")
	if err := os.Mkdir(cgroupPath, 0o755); err != nil { t.Fatal(err) }
	defer os.RemoveAll(cgroupPath)
	if err := os.Mkdir(childPath, 0o755); err != nil { t.Fatal(err) }
	info, err := os.Stat(cgroupPath)
	if err != nil { t.Fatal(err) }
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok { t.Fatal("cannot read cgroup inode") }

	exe, err := os.Executable()
	if err != nil { t.Fatal(err) }
	exeBytes, err := os.ReadFile(exe)
	if err != nil { t.Fatal(err) }
	artifactSum := sha256.Sum256(exeBytes)
	artifactSHA := hex.EncodeToString(artifactSum[:])
	writePath := filepath.Join(t.TempDir(), "preopened-blocked.txt")

	cmd := exec.Command(exe, "-test.run=^TestNodeShieldKernelHelper$")
	cmd.Env = append(os.Environ(),
		"NODESHIELD_KERNEL_HELPER=1",
		"NODESHIELD_ALLOWED4_ADDR="+allowed4.Addr().String(), "NODESHIELD_DENIED4_ADDR="+denied4.Addr().String(),
		"NODESHIELD_ALLOWED6_ADDR="+allowed6.Addr().String(), "NODESHIELD_DENIED6_ADDR="+denied6.Addr().String(),
		"NODESHIELD_WRITE_PATH="+writePath,
	)
	stdin, err := cmd.StdinPipe(); if err != nil { t.Fatal(err) }
	stdout, err := cmd.StdoutPipe(); if err != nil { t.Fatal(err) }
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil { t.Fatal(err) }
	defer func() { if cmd.Process != nil { _ = cmd.Process.Kill() } }()

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "READY" { t.Fatalf("helper did not become ready: %q", scanner.Text()) }
	// Put the workload in a CHILD cgroup before policy installation. The policy
	// is attached to the parent and must still mediate the descendant.
	if err := os.WriteFile(filepath.Join(childPath, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil { t.Fatal(err) }

	cfg := BPFLoadConfig{
		WorkloadID: "kernel-integration", CgroupPath: cgroupPath, CgroupID: st.Ino,
		ArtifactSHA256: artifactSHA, DenyExec: true, DenyFileWrite: true, DenyPrivilege: true,
		AllowedIPs: []BPFEndpoint{
			{Address: allowed4AP.Addr(), Port: allowed4AP.Port()},
			{Address: allowed6AP.Addr(), Port: allowed6AP.Port()},
		},
	}
	backend := NewLinuxCOREBackend(procExecutableVerifier{pid: cmd.Process.Pid})
	defer backend.Close()
	result, err := LoadVerifiedBPF(context.Background(), backend, cfg, manifest.Objects)
	if err != nil { t.Fatal(err) }
	if !result.SubtreeScoped || !result.DualStack || !result.FileIOCovered || !result.CredentialCovered || !result.FrozenDuringArm || !result.AtomicCgroupHandle {
		t.Fatalf("kernel coverage evidence incomplete: %#v", result)
	}

	if _, err := io.WriteString(stdin, "go\n"); err != nil { t.Fatal(err) }
	_ = stdin.Close()
	if !scanner.Scan() || scanner.Text() != "ENFORCEMENT_OK" { t.Fatalf("kernel enforcement proof failed: %q", scanner.Text()) }
	if err := cmd.Wait(); err != nil { t.Fatalf("helper failed: %v", err) }
	cmd.Process = nil
	if err := backend.CloseWorkload(cfg.WorkloadID); err != nil { t.Fatal(err) }
}

func drainOne(listener net.Listener) {
	conn, err := listener.Accept()
	if err == nil { _ = conn.Close() }
}
