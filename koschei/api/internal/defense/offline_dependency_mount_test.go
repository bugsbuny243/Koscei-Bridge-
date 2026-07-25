package defense

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendOfflineDependencySandboxArgsUsesReadOnlyFixedMounts(t *testing.T) {
	root := t.TempDir()
	vendor := filepath.Join(root, "vendor")
	writeOfflineVendorFixture(t, vendor, []string{"litesvm-0.6.1/src/lib.rs"})
	inventoryPath := filepath.Join(root, "inventory.json")
	configPath := filepath.Join(root, "cargo-config.toml")
	if err := os.WriteFile(inventoryPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(OfflineDependencyCargoConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	authorization := testOfflineDependencyMountAuthorization(inventoryPath, vendor, configPath)
	args, err := AppendOfflineDependencySandboxArgs([]string{"--unshare-all"}, authorization)
	if err != nil {
		t.Fatal(err)
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, expected := range []string{
		" --ro-bind " + vendor + " " + OfflineDependencyVendorPath + " ",
		" --ro-bind " + inventoryPath + " " + OfflineDependencyInventoryPath + " ",
		" --ro-bind " + configPath + " " + OfflineDependencyCargoConfigPath + " ",
		" --ro-bind " + configPath + " " + offlineDependencySandboxCargoConfigPath + " ",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("dependency sandbox mount is missing %q: %v", expected, args)
		}
	}
	if strings.Contains(joined, " --bind "+vendor+" ") || strings.Contains(joined, " --bind "+configPath+" ") || strings.Contains(joined, " --bind "+inventoryPath+" ") {
		t.Fatalf("dependency evidence received a writable bind: %v", args)
	}
	if authorization.NetworkAccess || authorization.DependencyResolution || authorization.VerdictAuthority {
		t.Fatalf("test authorization crossed a Phase 12C boundary: %+v", authorization)
	}
}

func TestAppendOfflineDependencySandboxArgsRejectsSymlinkAndMutableIdentity(t *testing.T) {
	root := t.TempDir()
	vendor := filepath.Join(root, "vendor")
	writeOfflineVendorFixture(t, vendor, []string{"litesvm-0.6.1/src/lib.rs"})
	inventoryPath := filepath.Join(root, "inventory.json")
	configPath := filepath.Join(root, "cargo-config.toml")
	if err := os.WriteFile(inventoryPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(OfflineDependencyCargoConfig), 0o644); err != nil {
		t.Fatal(err)
	}

	invalidImage := testOfflineDependencyMountAuthorization(inventoryPath, vendor, configPath)
	invalidImage.WorkerImageDigest = "latest"
	if _, err := AppendOfflineDependencySandboxArgs(nil, invalidImage); err == nil || !strings.Contains(err.Error(), DependencyInventoryMalformed) {
		t.Fatalf("mutable worker image was accepted for a dependency mount: %v", err)
	}
	mutableBoundary := testOfflineDependencyMountAuthorization(inventoryPath, vendor, configPath)
	mutableBoundary.NetworkAccess = true
	if _, err := AppendOfflineDependencySandboxArgs(nil, mutableBoundary); err == nil || !strings.Contains(err.Error(), DependencyInventoryMalformed) {
		t.Fatalf("network-enabled dependency authorization was accepted: %v", err)
	}

	linkPath := filepath.Join(root, "inventory-link.json")
	if err := os.Symlink(inventoryPath, linkPath); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	symlinkAuthorization := testOfflineDependencyMountAuthorization(linkPath, vendor, configPath)
	if _, err := AppendOfflineDependencySandboxArgs(nil, symlinkAuthorization); err == nil || !strings.Contains(err.Error(), DependencyInventoryPathEscape) {
		t.Fatalf("symlinked inventory source was accepted: %v", err)
	}
}

func testOfflineDependencyMountAuthorization(inventoryPath, vendorPath, configPath string) OfflineDependencyRuntimeAuthorization {
	return OfflineDependencyRuntimeAuthorization{
		InventoryRef:         "KODI1-0123456789abcdef0123456789abcdef",
		InventoryHash:        "sha256:" + strings.Repeat("a", 64),
		VendorTreeHash:       "sha256:" + strings.Repeat("b", 64),
		CargoManifestHash:    "sha256:" + strings.Repeat("c", 64),
		CargoLockHash:        "sha256:" + strings.Repeat("d", 64),
		CargoConfigHash:      "sha256:" + strings.Repeat("e", 64),
		PackageName:          OfflineDependencyPackageName,
		PackageVersion:       OfflineDependencyPackageVersion,
		FileCount:            1,
		TotalBytes:           1,
		WorkerID:             "ci-worker",
		WorkerImageDigest:    "sha256:" + strings.Repeat("f", 64),
		InventoryPath:        inventoryPath,
		VendorPath:           vendorPath,
		CargoConfigPath:      configPath,
		NetworkAccess:        false,
		DependencyResolution: false,
		VerdictAuthority:     false,
	}
}
