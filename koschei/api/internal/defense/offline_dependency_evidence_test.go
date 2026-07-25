package defense

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOfflineDependencyInventoryEvidenceIsImmutableAndIdempotent(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	root := t.TempDir()
	writeOfflineVendorFixture(t, root, []string{"litesvm-0.6.1/src/lib.rs", "serde-1.0.0/src/lib.rs"})
	inventory, err := BuildOfflineDependencyInventory(root, []byte(validLiteSVMCargoManifest()), []byte(validLiteSVMCargoLock()), []byte(OfflineDependencyCargoConfig))
	if err != nil {
		t.Fatal(err)
	}
	workerID := fmt.Sprintf("ci-offline-deps-%d", time.Now().UnixNano())
	imageDigest := "sha256:" + strings.Repeat("d", 64)
	observedAt := time.Now().UTC().Add(-time.Minute)
	first, err := PersistOfflineDependencyInventoryEvidence(ctx, db, workerID, imageDigest, inventory, observedAt, []string{"Reference image inventory only; production execution remains disabled."})
	if err != nil {
		t.Fatal(err)
	}
	second, err := PersistOfflineDependencyInventoryEvidence(ctx, db, workerID, imageDigest, inventory, observedAt.Add(time.Minute), nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.InventoryRef == "" || first.InventoryRef != second.InventoryRef || first.InventoryHash != inventory.InventoryHash {
		t.Fatalf("deterministic inventory evidence identity failed: first=%+v second=%+v", first, second)
	}
	if first.WorkerID != workerID || first.WorkerImageDigest != imageDigest || first.InventoryPath != OfflineDependencyInventoryPath ||
		first.VendorPath != OfflineDependencyVendorPath || first.CargoConfigPath != OfflineDependencyCargoConfigPath {
		t.Fatalf("inventory evidence identity/path binding is incomplete: %+v", first)
	}
	if first.EvidenceStatus != "verified" || first.FileCount != inventory.FileCount || first.TotalBytes != inventory.TotalBytes ||
		len(first.FileManifest) != inventory.FileCount || first.NetworkAccess || first.DependencyResolution || first.VerdictAuthority {
		t.Fatalf("inventory evidence crossed a Phase 12C boundary: %+v", first)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM defense_offline_dependency_inventories WHERE inventory_ref=$1`, first.InventoryRef).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("idempotent inventory persistence created %d rows", count)
	}
	if _, err := db.ExecContext(ctx, `UPDATE defense_offline_dependency_inventories SET evidence_status='rejected' WHERE inventory_ref=$1`, first.InventoryRef); err == nil {
		t.Fatal("immutable offline dependency inventory accepted an update")
	}
}

func TestOfflineDependencyInventoryEvidenceRejectsInvalidIdentityAndInventory(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	root := t.TempDir()
	writeOfflineVendorFixture(t, root, []string{"litesvm-0.6.1/src/lib.rs"})
	inventory, err := BuildOfflineDependencyInventory(root, []byte(validLiteSVMCargoManifest()), []byte(validLiteSVMCargoLock()), []byte(OfflineDependencyCargoConfig))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PersistOfflineDependencyInventoryEvidence(ctx, db, "worker", "latest", inventory, time.Time{}, nil); err == nil {
		t.Fatal("mutable worker image identity was accepted")
	}
	tampered := cloneOfflineDependencyInventory(inventory)
	tampered.Files[0].SizeBytes++
	if _, err := PersistOfflineDependencyInventoryEvidence(ctx, db, "worker", "sha256:"+strings.Repeat("e", 64), tampered, time.Time{}, nil); err == nil || !strings.Contains(err.Error(), DependencyInventoryMalformed) {
		t.Fatalf("tampered inventory evidence was accepted: %v", err)
	}
}
