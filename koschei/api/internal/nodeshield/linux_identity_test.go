//go:build linux

package nodeshield

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestMembershipContainsSubtree(t *testing.T) {
	raw := "0::/koschei/workload/child\n"
	if !membershipContainsSubtree(raw, "/koschei/workload") {
		t.Fatal("expected descendant cgroup membership to match")
	}
	if membershipContainsSubtree(raw, "/koschei/other") {
		t.Fatal("unexpected unrelated cgroup match")
	}
}

func TestLinuxProcIdentityVerifierBindsMembershipAndExecutableBytes(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	cgroupRoot := filepath.Join(root, "cgroup")
	protected := filepath.Join(cgroupRoot, "koschei", "workload")
	pidDir := filepath.Join(procRoot, "4242")
	if err := os.MkdirAll(protected, 0o755); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(pidDir, 0o755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/koschei/workload/child\n"), 0o600); err != nil { t.Fatal(err) }

	artifactPath := filepath.Join(root, "artifact")
	artifactBytes := []byte("verified workload executable")
	if err := os.WriteFile(artifactPath, artifactBytes, 0o700); err != nil { t.Fatal(err) }
	if err := os.Symlink(artifactPath, filepath.Join(pidDir, "exe")); err != nil { t.Fatal(err) }
	sum := sha256.Sum256(artifactBytes)

	verifier := LinuxProcIdentityVerifier{PID: 4242, ProcRoot: procRoot, CgroupRoot: cgroupRoot}
	cfg := BPFLoadConfig{CgroupPath: protected, ArtifactSHA256: hex.EncodeToString(sum[:])}
	if err := verifier.VerifyWorkloadIdentity(context.Background(), cfg); err != nil {
		t.Fatalf("expected verified identity: %v", err)
	}

	cfg.ArtifactSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := verifier.VerifyWorkloadIdentity(context.Background(), cfg); err == nil {
		t.Fatal("expected executable digest mismatch to fail closed")
	}
}

func TestLinuxProcIdentityVerifierRejectsWrongCgroup(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	cgroupRoot := filepath.Join(root, "cgroup")
	protected := filepath.Join(cgroupRoot, "koschei", "workload")
	pidDir := filepath.Join(procRoot, "4242")
	if err := os.MkdirAll(protected, 0o755); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(pidDir, 0o755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/other/workload\n"), 0o600); err != nil { t.Fatal(err) }
	artifactPath := filepath.Join(root, "artifact")
	artifactBytes := []byte("verified workload executable")
	if err := os.WriteFile(artifactPath, artifactBytes, 0o700); err != nil { t.Fatal(err) }
	if err := os.Symlink(artifactPath, filepath.Join(pidDir, "exe")); err != nil { t.Fatal(err) }
	sum := sha256.Sum256(artifactBytes)

	verifier := LinuxProcIdentityVerifier{PID: 4242, ProcRoot: procRoot, CgroupRoot: cgroupRoot}
	cfg := BPFLoadConfig{CgroupPath: protected, ArtifactSHA256: hex.EncodeToString(sum[:])}
	if err := verifier.VerifyWorkloadIdentity(context.Background(), cfg); err == nil {
		t.Fatal("expected wrong cgroup membership to fail closed")
	}
}
