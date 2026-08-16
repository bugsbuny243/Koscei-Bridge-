//go:build linux

package nodeshield

import (
	"os"
	"syscall"
	"testing"
)

func TestVerifyCgroupIdentityUsesDirectoryInode(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil { t.Fatal(err) }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok { t.Fatal("missing stat inode") }
	if err := verifyCgroupIdentity(dir, stat.Ino); err != nil {
		t.Fatalf("expected inode identity match: %v", err)
	}
	if err := verifyCgroupIdentity(dir, stat.Ino+1); err == nil {
		t.Fatal("expected mismatched cgroup identity to fail")
	}
}

func TestNodeShieldObjectPathsRequiresBothObjects(t *testing.T) {
	_, _, err := nodeShieldObjectPaths([]BPFObjectManifest{{Name: "nodeshield_lsm", Path: "/tmp/lsm.o"}})
	if err == nil { t.Fatal("expected missing connect object to fail") }

	lsm, connect, err := nodeShieldObjectPaths([]BPFObjectManifest{
		{Name: "nodeshield_lsm", Path: "/tmp/lsm.o"},
		{Name: "nodeshield_connect", Path: "/tmp/connect.o"},
	})
	if err != nil { t.Fatal(err) }
	if lsm != "/tmp/lsm.o" || connect != "/tmp/connect.o" { t.Fatal("unexpected object paths") }
}
