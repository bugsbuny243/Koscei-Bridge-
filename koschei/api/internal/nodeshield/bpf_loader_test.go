package nodeshield

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

type fakeBPFBackend struct {
	result BPFLoadResult
	err    error
}

func (f fakeBPFBackend) LoadAndAttach(_ context.Context, _ []BPFObjectManifest) (BPFLoadResult, error) {
	return f.result, f.err
}

func testBPFManifest(t *testing.T) BPFObjectManifest {
	t.Helper()
	path := filepath.Join(t.TempDir(), "program.o")
	data := []byte("object")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return BPFObjectManifest{Name: "test", Path: path, SHA256: hex.EncodeToString(sum[:])}
}

func TestLoadVerifiedBPFRequiresCompleteAttachmentState(t *testing.T) {
	backend := fakeBPFBackend{result: BPFLoadResult{LSMAttached: true, ConnectAttached: true, PolicyMapsReady: false, ArtifactBound: true}}
	if _, err := LoadVerifiedBPF(context.Background(), backend, []BPFObjectManifest{testBPFManifest(t)}); err == nil {
		t.Fatal("expected incomplete policy map state to fail closed")
	}
}

func TestLoadVerifiedBPFAcceptsCompleteState(t *testing.T) {
	backend := fakeBPFBackend{result: BPFLoadResult{LSMAttached: true, ConnectAttached: true, PolicyMapsReady: true, ArtifactBound: true}}
	result, err := LoadVerifiedBPF(context.Background(), backend, []BPFObjectManifest{testBPFManifest(t)})
	if err != nil {
		t.Fatalf("expected complete BPF state: %v", err)
	}
	if !result.ObjectsVerified {
		t.Fatal("expected object verification to be recorded")
	}
}
