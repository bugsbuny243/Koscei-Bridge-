//go:build linux

package nodeshield

import (
	"context"
	"os"
	"syscall"
	"testing"
)

func TestOpenVerifiedCgroupUsesDirectoryInode(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil { t.Fatal(err) }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok { t.Fatal("missing stat inode") }
	f, err := openVerifiedCgroup(dir, stat.Ino)
	if err != nil { t.Fatalf("expected inode identity match: %v", err) }
	_ = f.Close()
	if _, err := openVerifiedCgroup(dir, stat.Ino+1); err == nil { t.Fatal("expected mismatched cgroup identity to fail") }
}

func TestNodeShieldObjectBytesRequiresBothObjects(t *testing.T) {
	_, _, err := nodeShieldObjectBytes([]VerifiedBPFObject{{Name: "nodeshield_lsm", Bytes: []byte("lsm")}})
	if err == nil { t.Fatal("expected missing connect object to fail") }
	lsm, connect, err := nodeShieldObjectBytes([]VerifiedBPFObject{
		{Name: "nodeshield_lsm", Bytes: []byte("lsm")},
		{Name: "nodeshield_connect", Bytes: []byte("connect")},
	})
	if err != nil { t.Fatal(err) }
	if string(lsm) != "lsm" || string(connect) != "connect" { t.Fatal("unexpected verified object bytes") }
}

func TestLinuxCOREBackendCloseIsIdempotentAndRejectsFutureLoads(t *testing.T) {
	backend := NewLinuxCOREBackend(nil)
	if err := backend.Close(); err != nil { t.Fatalf("close backend: %v", err) }
	if err := backend.Close(); err != nil { t.Fatalf("second close must be idempotent: %v", err) }

	_, err := backend.LoadAndAttach(context.Background(), BPFLoadConfig{}, nil)
	if err == nil { t.Fatal("expected closed backend to reject future load") }
	if got := err.Error(); got != "linux CO-RE backend is closed" {
		t.Fatalf("expected closed-backend error before any load side effect, got %q", got)
	}
}
