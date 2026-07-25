package defense

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendOfflineDependencySandboxArgsInsertsBeforeFixedCommand(t *testing.T) {
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
	base := []string{"--unshare-all", "--", "/usr/bin/cargo", "test", "--locked", "--offline"}
	args, err := AppendOfflineDependencySandboxArgs(base, authorization)
	if err != nil {
		t.Fatal(err)
	}
	separator := -1
	vendorMount := -1
	for index, value := range args {
		if value == "--" && separator < 0 {
			separator = index
		}
		if value == authorization.VendorPath {
			vendorMount = index
		}
	}
	if separator < 0 || vendorMount < 0 || vendorMount >= separator {
		t.Fatalf("dependency mounts were not inserted before the fixed command: %v", args)
	}
	if strings.Join(args[separator+1:], " ") != "/usr/bin/cargo test --locked --offline" {
		t.Fatalf("fixed final command moved or changed: %v", args)
	}
}
