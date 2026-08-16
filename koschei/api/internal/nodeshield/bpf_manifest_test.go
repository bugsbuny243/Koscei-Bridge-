package nodeshield

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyBPFObjectManifestAcceptsMatchingDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "program.o")
	data := []byte("verified-object")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	manifest := BPFObjectManifest{Name: "lsm", Path: path, SHA256: hex.EncodeToString(sum[:])}
	if err := VerifyBPFObjectManifest(manifest); err != nil {
		t.Fatalf("expected matching object digest: %v", err)
	}
}

func TestVerifyBPFObjectManifestRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "program.o")
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := BPFObjectManifest{Name: "lsm", Path: path, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := VerifyBPFObjectManifest(manifest); err == nil {
		t.Fatal("expected object digest mismatch")
	}
}
