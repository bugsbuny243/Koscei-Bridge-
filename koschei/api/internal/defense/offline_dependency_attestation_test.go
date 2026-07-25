package defense

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAttestOfflineDependencyRuntimeStorePersistsVerifiedImageEvidence(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	root := t.TempDir()
	vendorRoot := filepath.Join(root, "vendor")
	writeOfflineVendorFixture(t, vendorRoot, []string{"litesvm-0.6.1/src/lib.rs", "serde-1.0.0/src/lib.rs"})
	inventory, err := BuildOfflineDependencyInventory(vendorRoot, []byte(validLiteSVMCargoManifest()), []byte(validLiteSVMCargoLock()), []byte(OfflineDependencyCargoConfig))
	if err != nil {
		t.Fatal(err)
	}
	inventoryRaw, err := MarshalOfflineDependencyInventory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "inventory.json"), inventoryRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cargo-config.toml"), []byte(OfflineDependencyCargoConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	workerID := "ci-attest-offline-store"
	imageDigest := "sha256:" + strings.Repeat("a", 64)
	first, err := attestOfflineDependencyRuntimeStoreAtRoot(ctx, db, workerID, imageDigest, root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := attestOfflineDependencyRuntimeStoreAtRoot(ctx, db, workerID, imageDigest, root)
	if err != nil {
		t.Fatal(err)
	}
	if first.InventoryRef == "" || first.InventoryRef != second.InventoryRef || first.InventoryHash != inventory.InventoryHash || first.EvidenceStatus != "verified" || first.NetworkAccess || first.DependencyResolution || first.VerdictAuthority {
		t.Fatalf("runtime store attestation is incomplete or non-idempotent: first=%+v second=%+v", first, second)
	}
}

func TestAttestOfflineDependencyRuntimeStoreRejectsMutatedImageContent(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	root := t.TempDir()
	vendorRoot := filepath.Join(root, "vendor")
	writeOfflineVendorFixture(t, vendorRoot, []string{"litesvm-0.6.1/src/lib.rs"})
	inventory, err := BuildOfflineDependencyInventory(vendorRoot, []byte(validLiteSVMCargoManifest()), []byte(validLiteSVMCargoLock()), []byte(OfflineDependencyCargoConfig))
	if err != nil {
		t.Fatal(err)
	}
	inventoryRaw, err := MarshalOfflineDependencyInventory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "inventory.json"), inventoryRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cargo-config.toml"), []byte(OfflineDependencyCargoConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorRoot, "litesvm-0.6.1", "src", "lib.rs"), []byte("mutated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := attestOfflineDependencyRuntimeStoreAtRoot(ctx, db, "ci-worker", "sha256:"+strings.Repeat("b", 64), root); err == nil || !strings.Contains(err.Error(), DependencyInventoryFileMismatch) {
		t.Fatalf("mutated image dependency content was attested: %v", err)
	}
}
