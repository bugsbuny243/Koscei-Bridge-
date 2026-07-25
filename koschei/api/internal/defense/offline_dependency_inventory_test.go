package defense

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOfflineDependencyInventoryIsDeterministicAcrossCreationOrder(t *testing.T) {
	firstRoot := t.TempDir()
	secondRoot := t.TempDir()
	writeOfflineVendorFixture(t, firstRoot, []string{"zeta/src/lib.rs", "alpha/.cargo-checksum.json", "alpha/src/lib.rs"})
	writeOfflineVendorFixture(t, secondRoot, []string{"alpha/src/lib.rs", "zeta/src/lib.rs", "alpha/.cargo-checksum.json"})

	manifest := []byte(validLiteSVMCargoManifest())
	lock := []byte(validLiteSVMCargoLock())
	config := []byte(OfflineDependencyCargoConfig)
	first, err := BuildOfflineDependencyInventory(firstRoot, manifest, lock, config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildOfflineDependencyInventory(secondRoot, manifest, lock, config)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("identical vendor content produced different inventory evidence:\nfirst=%+v\nsecond=%+v", first, second)
	}
	firstJSON, err := MarshalOfflineDependencyInventory(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := MarshalOfflineDependencyInventory(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) || bytes.Contains(firstJSON, []byte("observed_at")) || bytes.Contains(firstJSON, []byte("created_at")) {
		t.Fatalf("inventory JSON is not deterministic and timestamp-free:\n%s", firstJSON)
	}
	if first.FileCount != 3 || first.TotalBytes <= 0 || first.InventoryHash == "" || first.VendorTreeHash == "" || first.NetworkAccess || first.DependencyResolution {
		t.Fatalf("inventory boundary or totals are incomplete: %+v", first)
	}
	if got := []string{first.Files[0].Path, first.Files[1].Path, first.Files[2].Path}; !reflect.DeepEqual(got, []string{"alpha/.cargo-checksum.json", "alpha/src/lib.rs", "zeta/src/lib.rs"}) {
		t.Fatalf("inventory paths are not canonical and sorted: %v", got)
	}
}

func TestVerifyOfflineDependencyInventoryRejectsChangedMissingAndExtraFiles(t *testing.T) {
	root := t.TempDir()
	writeOfflineVendorFixture(t, root, []string{"alpha/src/lib.rs", "beta/src/lib.rs"})
	manifest := []byte(validLiteSVMCargoManifest())
	lock := []byte(validLiteSVMCargoLock())
	config := []byte(OfflineDependencyCargoConfig)
	expected, err := BuildOfflineDependencyInventory(root, manifest, lock, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOfflineDependencyInventory(root, manifest, lock, config, expected); err != nil {
		t.Fatalf("unchanged vendor tree was rejected: %v", err)
	}

	alpha := filepath.Join(root, "alpha", "src", "lib.rs")
	if err := os.WriteFile(alpha, []byte("pub fn alpha() -> u64 { 99 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOfflineDependencyInventory(root, manifest, lock, config, expected); err == nil || !strings.Contains(err.Error(), DependencyInventoryFileMismatch) {
		t.Fatalf("changed vendor byte was not rejected: %v", err)
	}
	if err := os.WriteFile(alpha, offlineVendorFixtureContent("alpha/src/lib.rs"), 0o644); err != nil {
		t.Fatal(err)
	}

	beta := filepath.Join(root, "beta", "src", "lib.rs")
	if err := os.Remove(beta); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOfflineDependencyInventory(root, manifest, lock, config, expected); err == nil || !strings.Contains(err.Error(), DependencyInventoryFileMissing) {
		t.Fatalf("missing vendor file was not rejected: %v", err)
	}
	if err := os.WriteFile(beta, offlineVendorFixtureContent("beta/src/lib.rs"), 0o644); err != nil {
		t.Fatal(err)
	}

	extra := filepath.Join(root, "gamma", "src", "lib.rs")
	if err := os.MkdirAll(filepath.Dir(extra), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extra, []byte("pub fn gamma() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOfflineDependencyInventory(root, manifest, lock, config, expected); err == nil || !strings.Contains(err.Error(), DependencyInventoryFileMismatch) {
		t.Fatalf("extra vendor file was not rejected: %v", err)
	}
}

func TestOfflineDependencyInventoryRejectsSymlinkAndNonCanonicalManifestPaths(t *testing.T) {
	root := t.TempDir()
	writeOfflineVendorFixture(t, root, []string{"alpha/src/lib.rs", "beta/src/lib.rs"})
	link := filepath.Join(root, "alpha", "escape")
	if err := os.Symlink(filepath.Join(root, "beta", "src", "lib.rs"), link); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	manifest := []byte(validLiteSVMCargoManifest())
	lock := []byte(validLiteSVMCargoLock())
	config := []byte(OfflineDependencyCargoConfig)
	if _, err := BuildOfflineDependencyInventory(root, manifest, lock, config); err == nil || !strings.Contains(err.Error(), DependencyInventoryPathEscape) {
		t.Fatalf("vendor symlink was not rejected: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	inventory, err := BuildOfflineDependencyInventory(root, manifest, lock, config)
	if err != nil {
		t.Fatal(err)
	}

	duplicate := cloneOfflineDependencyInventory(inventory)
	duplicate.Files[1].Path = duplicate.Files[0].Path
	if err := ValidateOfflineDependencyInventory(duplicate); err == nil || !strings.Contains(err.Error(), DependencyInventoryMalformed) {
		t.Fatalf("duplicate inventory path was not rejected: %v", err)
	}
	pathEscape := cloneOfflineDependencyInventory(inventory)
	pathEscape.Files[0].Path = "../outside"
	if err := ValidateOfflineDependencyInventory(pathEscape); err == nil || !strings.Contains(err.Error(), DependencyInventoryPathEscape) {
		t.Fatalf("path escape was not rejected: %v", err)
	}
	unsorted := cloneOfflineDependencyInventory(inventory)
	unsorted.Files[0], unsorted.Files[1] = unsorted.Files[1], unsorted.Files[0]
	if err := ValidateOfflineDependencyInventory(unsorted); err == nil || !strings.Contains(err.Error(), DependencyInventoryMalformed) {
		t.Fatalf("unsorted inventory was not rejected: %v", err)
	}
}

func TestVerifyOfflineDependencyInventoryBindsCargoInputs(t *testing.T) {
	root := t.TempDir()
	writeOfflineVendorFixture(t, root, []string{"litesvm-0.6.1/src/lib.rs"})
	manifest := []byte(validLiteSVMCargoManifest())
	lock := []byte(validLiteSVMCargoLock())
	config := []byte(OfflineDependencyCargoConfig)
	expected, err := BuildOfflineDependencyInventory(root, manifest, lock, config)
	if err != nil {
		t.Fatal(err)
	}

	changedManifest := append(append([]byte(nil), manifest...), '\n')
	if err := VerifyOfflineDependencyInventory(root, changedManifest, lock, config, expected); err == nil || !strings.Contains(err.Error(), DependencyInventoryHashMismatch) {
		t.Fatalf("changed Cargo.toml was not rejected: %v", err)
	}
	changedLock := append(append([]byte(nil), lock...), '\n')
	if err := VerifyOfflineDependencyInventory(root, manifest, changedLock, config, expected); err == nil || !strings.Contains(err.Error(), DependencyLockMismatch) {
		t.Fatalf("changed Cargo.lock was not rejected: %v", err)
	}
	changedConfig := []byte(strings.Replace(OfflineDependencyCargoConfig, "offline = true", "offline = false", 1))
	if err := VerifyOfflineDependencyInventory(root, manifest, lock, changedConfig, expected); err == nil || !strings.Contains(err.Error(), DependencyCargoConfigMismatch) {
		t.Fatalf("changed Cargo source replacement was not rejected: %v", err)
	}
	if _, err := BuildOfflineDependencyInventory("relative/vendor", manifest, lock, config); err == nil || !strings.Contains(err.Error(), DependencyInventoryUnavailable) {
		t.Fatalf("relative vendor root was not rejected: %v", err)
	}
}

func writeOfflineVendorFixture(t *testing.T, root string, paths []string) {
	t.Helper()
	for _, relative := range paths {
		full := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, offlineVendorFixtureContent(relative), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func offlineVendorFixtureContent(relative string) []byte {
	return []byte("fixture:" + relative + "\n")
}

func cloneOfflineDependencyInventory(inventory OfflineDependencyInventory) OfflineDependencyInventory {
	clone := inventory
	clone.Files = append([]OfflineDependencyInventoryFile(nil), inventory.Files...)
	return clone
}
