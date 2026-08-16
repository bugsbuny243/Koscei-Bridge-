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
)

type integrationManifest struct {
	Schema  string              `json:"schema"`
	Objects []BPFObjectManifest `json:"objects"`
}

type procExecutableVerifier struct{ pid int }

func (v procExecutableVerifier) VerifyWorkloadIdentity(_ context.Context, cfg BPFLoadConfig) error {
	procs, err := os.ReadFile(filepath.Join(cfg.CgroupPath, "cgroup.procs"))
	if err != nil { return err }
	needle := strconv.Itoa(v.pid)
	found := false
	for _, line := range strings.Fields(string(procs)) {
		if line == needle { found = true; break }
	}
	if !found { return fmt.Errorf("pid %d is not in protected cgroup", v.pid) }

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
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintln(os.Stdout, "READY")
	if _, err := reader.ReadString('\n'); err != nil { t.Fatal(err) }

	allowed := os.Getenv("NODESHIELD_ALLOWED_ADDR")
	denied := os.Getenv("NODESHIELD_DENIED_ADDR")
	writePath := os.Getenv("NODESHIELD_WRITE_PATH")

	conn, err := net.DialTimeout("tcp4", allowed, 2*time.Second)
	if err != nil { t.Fatalf("allowed connect was blocked: %v", err) }
	_ = conn.Close()

	if conn, err := net.DialTimeout("tcp4", denied, 2*time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("unauthorized connect unexpectedly succeeded")
	}

	if err := os.WriteFile(writePath, []byte("must-not-write"), 0o600); err == nil {
		t.Fatal("forbidden file write unexpectedly succeeded")
	}

	if err := syscall.Setuid(65534); err == nil {
		t.Fatal("forbidden credential change unexpectedly succeeded")
	}

	if err := syscall.Exec("/bin/true", []string{"true"}, os.Environ()); err == nil {
		t.Fatal("forbidden exec unexpectedly succeeded")
	}

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

	allowedListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer allowedListener.Close()
	deniedListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer deniedListener.Close()
	go drainOne(allowedListener)
	go drainOne(deniedListener)

	allowedAP, err := netip.ParseAddrPort(allowedListener.Addr().String())
	if err != nil { t.Fatal(err) }

	cgroupPath := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("koschei-nodeshield-it-%d", os.Getpid()))
	if err := os.Mkdir(cgroupPath, 0o755); err != nil { t.Fatal(err) }
	defer os.Remove(cgroupPath)
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

	cmd := exec.Command(exe, "-test.run=^TestNodeShieldKernelHelper$")
	cmd.Env = append(os.Environ(),
		"NODESHIELD_KERNEL_HELPER=1",
		"NODESHIELD_ALLOWED_ADDR="+allowedListener.Addr().String(),
		"NODESHIELD_DENIED_ADDR="+deniedListener.Addr().String(),
		"NODESHIELD_WRITE_PATH="+filepath.Join(t.TempDir(), "blocked.txt"),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil { t.Fatal(err) }
	stdout, err := cmd.StdoutPipe()
	if err != nil { t.Fatal(err) }
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil { t.Fatal(err) }
	defer func() { if cmd.Process != nil { _ = cmd.Process.Kill() } }()

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "READY" { t.Fatalf("helper did not become ready: %q", scanner.Text()) }
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil { t.Fatal(err) }

	cfg := BPFLoadConfig{
		WorkloadID: "kernel-integration",
		CgroupPath: cgroupPath,
		CgroupID: st.Ino,
		ArtifactSHA256: artifactSHA,
		DenyExec: true,
		DenyFileWrite: true,
		DenyPrivilege: true,
		AllowedIPv4: []BPFEndpoint4{{Address: allowedAP.Addr(), Port: allowedAP.Port()}},
	}
	backend := NewLinuxCOREBackend(procExecutableVerifier{pid: cmd.Process.Pid})
	defer backend.Close()
	if _, err := LoadVerifiedBPF(context.Background(), backend, cfg, manifest.Objects); err != nil { t.Fatal(err) }

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
