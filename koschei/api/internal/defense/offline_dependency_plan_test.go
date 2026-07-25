package defense

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBindOfflineDependencyAuthorizationToPlanIsDeterministicAndImmutable(t *testing.T) {
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

	first := testLiteSVMSandboxPlan(t)
	first.InputHash = "sha256:" + strings.Repeat("1", 64)
	second := first
	second.SandboxPolicy = cloneStringAnyMap(first.SandboxPolicy)
	if err := BindOfflineDependencyAuthorizationToPlan(&first, authorization); err != nil {
		t.Fatal(err)
	}
	if err := BindOfflineDependencyAuthorizationToPlan(&second, authorization); err != nil {
		t.Fatal(err)
	}
	if first.SandboxPolicyHash != second.SandboxPolicyHash || first.InputHash != second.InputHash {
		t.Fatalf("identical dependency evidence produced different plan identities: first=%+v second=%+v", first, second)
	}
	raw, ok := first.SandboxPolicy[offlineDependencySandboxPolicyKey].(map[string]any)
	if !ok || raw["inventory_ref"] != authorization.InventoryRef || raw["inventory_hash"] != authorization.InventoryHash || raw["mount_mode"] != "read_only" || raw["network_access"] != false || raw["dependency_resolution"] != false || raw["verdict_authority"] != false {
		t.Fatalf("dependency evidence was not retained in the sandbox policy: %#v", first.SandboxPolicy)
	}
	if first.SandboxPolicyHash != hashValue(first.SandboxPolicy) || first.InputHash == "" {
		t.Fatalf("bound plan hashes are invalid: %+v", first)
	}
}

func TestBindOfflineDependencyAuthorizationToPlanRejectsIncompletePlan(t *testing.T) {
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
	if err := BindOfflineDependencyAuthorizationToPlan(&LiteSVMExecutionPlan{}, authorization); err == nil || !strings.Contains(err.Error(), DependencyInventoryMalformed) {
		t.Fatalf("incomplete LiteSVM plan was accepted: %v", err)
	}
}

func TestOfflineDependencyTerminationReasonIsStable(t *testing.T) {
	for _, reason := range []string{DependencyInventoryUnavailable, DependencyInventoryMalformed, DependencyInventoryFileMismatch, DependencyLockMismatch, DependencyCargoConfigMismatch} {
		if got := OfflineDependencyTerminationReason(assertiveError(reason + ": fixture")); got != reason {
			t.Fatalf("termination reason changed: input=%s got=%s", reason, got)
		}
	}
	if got := OfflineDependencyTerminationReason(assertiveError("unclassified")); got != DependencyInventoryUnavailable {
		t.Fatalf("unknown dependency failure did not fail closed: %s", got)
	}
}

type assertiveError string

func (e assertiveError) Error() string { return string(e) }

func cloneStringAnyMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
