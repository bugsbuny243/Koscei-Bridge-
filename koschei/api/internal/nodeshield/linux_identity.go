//go:build linux

package nodeshield

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LinuxProcIdentityVerifier verifies a protected process against both the
// selected cgroup subtree and the exact executable inode exposed by procfs.
// It intentionally opens /proc/<pid>/exe directly instead of resolving the
// pathname and reopening it, avoiding pathname replacement races.
type LinuxProcIdentityVerifier struct {
	PID        int
	ProcRoot   string
	CgroupRoot string
}

func NewLinuxProcIdentityVerifier(pid int) LinuxProcIdentityVerifier {
	return LinuxProcIdentityVerifier{PID: pid, ProcRoot: "/proc", CgroupRoot: "/sys/fs/cgroup"}
}

func (v LinuxProcIdentityVerifier) VerifyWorkloadIdentity(ctx context.Context, cfg BPFLoadConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.PID <= 0 {
		return fmt.Errorf("workload pid must be positive")
	}
	procRoot := v.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	cgroupRoot := v.CgroupRoot
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}

	rootAbs, err := filepath.Abs(cgroupRoot)
	if err != nil {
		return fmt.Errorf("resolve cgroup root: %w", err)
	}
	pathAbs, err := filepath.Abs(cfg.CgroupPath)
	if err != nil {
		return fmt.Errorf("resolve protected cgroup: %w", err)
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return fmt.Errorf("relativize protected cgroup: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("protected cgroup is outside configured cgroup root")
	}
	want := "/" + strings.TrimPrefix(filepath.ToSlash(rel), "/")
	if want == "/." {
		want = "/"
	}

	pidDir := filepath.Join(procRoot, strconv.Itoa(v.PID))
	membership, err := os.ReadFile(filepath.Join(pidDir, "cgroup"))
	if err != nil {
		return fmt.Errorf("read workload cgroup membership: %w", err)
	}
	if !membershipContainsSubtree(string(membership), want) {
		return fmt.Errorf("pid %d is not in protected cgroup subtree %s", v.PID, want)
	}

	exe, err := os.Open(filepath.Join(pidDir, "exe"))
	if err != nil {
		return fmt.Errorf("open running executable identity: %w", err)
	}
	defer exe.Close()

	h := sha256.New()
	if _, err := io.Copy(h, exe); err != nil {
		return fmt.Errorf("hash running executable: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, cfg.ArtifactSHA256) {
		return fmt.Errorf("running executable sha256 mismatch")
	}
	return nil
}

func membershipContainsSubtree(raw, want string) bool {
	want = "/" + strings.Trim(strings.TrimSpace(want), "/")
	if want == "//" {
		want = "/"
	}
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" {
			continue
		}
		got := strings.TrimSpace(parts[2])
		if want == "/" {
			if strings.HasPrefix(got, "/") {
				return true
			}
			continue
		}
		if got == want || strings.HasPrefix(got, strings.TrimSuffix(want, "/")+"/") {
			return true
		}
	}
	return false
}
