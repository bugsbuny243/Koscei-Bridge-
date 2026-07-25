package defense

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthorizeOfflineDependencyRuntimeRehashesAndBindsEvidence(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	profile := createMaterializationTestProfile(t, ctx, db, validLiteSVMCargoManifest(), validLiteSVMCargoLock(), "#[test]\nfn invariant() { assert!(true); }\n")
	materialization, err := CreateHarnessMaterialization(ctx, db, HarnessMaterializationInput{ProfileRef: profile.ProfileRef})
	if err != nil {
		t.Fatal(err)
	}
	root, inventory := installOfflineDependencyRuntimeFixture(t, profile, materialization)
	if _, err := PersistOfflineDependencyInventoryEvidence(ctx, db, profile.WorkerID, profile.WorkerImageDigest, inventory, time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}

	authorized, err := authorizeOfflineDependencyRuntimeAtRoot(ctx, db, profile.WorkerID, profile.WorkerImageDigest, materialization.MaterializationRef, root)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.InventoryRef == "" || authorized.InventoryHash != inventory.InventoryHash || authorized.VendorTreeHash != inventory.VendorTreeHash ||
		authorized.CargoManifestHash != materialization.CargoManifestHash || authorized.CargoLockHash != materialization.CargoLockHash ||
		authorized.WorkerID != profile.WorkerID || authorized.WorkerImageDigest != profile.WorkerImageDigest ||
		authorized.InventoryPath != filepath.Join(root, "inventory.json") || authorized.VendorPath != filepath.Join(root, "vendor") ||
		authorized.CargoConfigPath != filepath.Join(root, "cargo-config.toml") || authorized.NetworkAccess || authorized.DependencyResolution || authorized.VerdictAuthority {
		t.Fatalf("runtime authorization is incomplete or crossed a boundary: %+v", authorized)
	}
}

func TestAuthorizeOfflineDependencyRuntimeFailsClosedBeforeLaunchOnMismatch(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	profile := createMaterializationTestProfile(t, ctx, db, validLiteSVMCargoManifest(), validLiteSVMCargoLock(), "#[test]\nfn invariant() { assert!(true); }\n")
	materialization, err := CreateHarnessMaterialization(ctx, db, HarnessMaterializationInput{ProfileRef: profile.ProfileRef})
	if err != nil {
		t.Fatal(err)
	}
	root, inventory := installOfflineDependencyRuntimeFixture(t, profile, materialization)
	if _, err := PersistOfflineDependencyInventoryEvidence(ctx, db, profile.WorkerID, profile.WorkerImageDigest, inventory, time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}

	if _, err := authorizeOfflineDependencyRuntimeAtRoot(ctx, db, profile.WorkerID, "sha256:"+strings.Repeat("f", 64), materialization.MaterializationRef, root); err == nil || !strings.Contains(err.Error(), DependencyInventoryUnavailable) {
		t.Fatalf("mismatched worker image was authorized: %v", err)
	}

	vendorFile := filepath.Join(root, "vendor", "litesvm-0.6.1", "src", "lib.rs")
	original, err := os.ReadFile(vendorFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vendorFile, []byte("pub fn changed() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := authorizeOfflineDependencyRuntimeAtRoot(ctx, db, profile.WorkerID, profile.WorkerImageDigest, materialization.MaterializationRef, root); err == nil || !strings.Contains(err.Error(), DependencyInventoryFileMismatch) {
		t.Fatalf("changed vendor byte was authorized: %v", err)
	}
	if err := os.WriteFile(vendorFile, original, 0o644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(root, "cargo-config.toml")
	if err := os.WriteFile(configPath, []byte(strings.Replace(OfflineDependencyCargoConfig, "offline = true", "offline = false", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := authorizeOfflineDependencyRuntimeAtRoot(ctx, db, profile.WorkerID, profile.WorkerImageDigest, materialization.MaterializationRef, root); err == nil || !strings.Contains(err.Error(), DependencyCargoConfigMismatch) {
		t.Fatalf("changed Cargo config was authorized: %v", err)
	}
}

func TestAuthorizeOfflineDependencyRuntimeRejectsNonCanonicalInventoryJSON(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	profile := createMaterializationTestProfile(t, ctx, db, validLiteSVMCargoManifest(), validLiteSVMCargoLock(), "#[test]\nfn invariant() { assert!(true); }\n")
	materialization, err := CreateHarnessMaterialization(ctx, db, HarnessMaterializationInput{ProfileRef: profile.ProfileRef})
	if err != nil {
		t.Fatal(err)
	}
	root, inventory := installOfflineDependencyRuntimeFixture(t, profile, materialization)
	if _, err := PersistOfflineDependencyInventoryEvidence(ctx, db, profile.WorkerID, profile.WorkerImageDigest, inventory, time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	inventoryPath := filepath.Join(root, "inventory.json")
	raw, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventoryPath, append([]byte(" \n"), raw...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := authorizeOfflineDependencyRuntimeAtRoot(ctx, db, profile.WorkerID, profile.WorkerImageDigest, materialization.MaterializationRef, root); err == nil || !strings.Contains(err.Error(), DependencyInventoryMalformed) {
		t.Fatalf("non-canonical inventory JSON was authorized: %v", err)
	}
}

func installOfflineDependencyRuntimeFixture(t *testing.T, profile HarnessExecutionProfile, materialization HarnessMaterialization) (string, OfflineDependencyInventory) {
	t.Helper()
	root := t.TempDir()
	vendorRoot := filepath.Join(root, "vendor")
	writeOfflineVendorFixture(t, vendorRoot, []string{"litesvm-0.6.1/src/lib.rs", "serde-1.0.0/src/lib.rs"})
	artifactDB := defenseWorkerTestDB(t)
	defer artifactDB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	artifact, err := LoadArtifact(ctx, artifactDB, materialization.MaterializedArtifactRef)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := decodeSourceBundle(artifact.Content)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := BuildOfflineDependencyInventory(vendorRoot, []byte(bundle["Cargo.toml"]), []byte(bundle["Cargo.lock"]), []byte(OfflineDependencyCargoConfig))
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
	return root, inventory
}
