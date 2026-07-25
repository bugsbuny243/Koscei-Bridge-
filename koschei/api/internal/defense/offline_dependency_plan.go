package defense

import "errors"

const offlineDependencySandboxPolicyKey = "offline_dependency_inventory"

// BindOfflineDependencyAuthorizationToPlan makes the exact inventory reference
// and hashes part of the immutable sandbox and input identities retained by the
// Phase 12C attempt record.
func BindOfflineDependencyAuthorizationToPlan(plan *LiteSVMExecutionPlan, authorization OfflineDependencyRuntimeAuthorization) error {
	if plan == nil || len(plan.SandboxPolicy) == 0 || plan.SandboxPolicyHash == "" || plan.SandboxPolicyHash != hashValue(plan.SandboxPolicy) || plan.InputHash == "" {
		return errors.New(DependencyInventoryMalformed + ": LiteSVM plan is not ready for dependency binding")
	}
	if err := validateOfflineDependencyRuntimeAuthorization(authorization); err != nil {
		return err
	}
	evidence := map[string]any{
		"inventory_ref":          authorization.InventoryRef,
		"inventory_hash":         authorization.InventoryHash,
		"vendor_tree_hash":       authorization.VendorTreeHash,
		"cargo_manifest_hash":    authorization.CargoManifestHash,
		"cargo_lock_hash":        authorization.CargoLockHash,
		"cargo_config_hash":      authorization.CargoConfigHash,
		"package_name":           authorization.PackageName,
		"package_version":        authorization.PackageVersion,
		"file_count":             authorization.FileCount,
		"total_bytes":            authorization.TotalBytes,
		"worker_id":              authorization.WorkerID,
		"worker_image_digest":    authorization.WorkerImageDigest,
		"inventory_path":         OfflineDependencyInventoryPath,
		"vendor_path":            OfflineDependencyVendorPath,
		"cargo_config_path":      OfflineDependencyCargoConfigPath,
		"sandbox_cargo_config":   offlineDependencySandboxCargoConfigPath,
		"mount_mode":             "read_only",
		"network_access":         false,
		"dependency_resolution":  false,
		"verdict_authority":      false,
	}
	plan.SandboxPolicy[offlineDependencySandboxPolicyKey] = evidence
	plan.SandboxPolicyHash = hashValue(plan.SandboxPolicy)
	plan.InputHash = hashValue(map[string]any{
		"base_input_hash":             plan.InputHash,
		"offline_dependency_inventory": evidence,
		"sandbox_policy_hash":          plan.SandboxPolicyHash,
	})
	return nil
}

func OfflineDependencyTerminationReason(err error) string {
	if err == nil {
		return DependencyInventoryUnavailable
	}
	value := err.Error()
	for _, reason := range []string{
		DependencyInventoryUnavailable,
		DependencyInventoryMalformed,
		DependencyInventoryPathEscape,
		DependencyInventoryFileMissing,
		DependencyInventoryFileMismatch,
		DependencyInventoryHashMismatch,
		DependencyLockMismatch,
		DependencyLiteSVMVersionMismatch,
		DependencyCargoConfigMismatch,
	} {
		if len(value) >= len(reason) && value[:len(reason)] == reason {
			return reason
		}
	}
	return DependencyInventoryUnavailable
}
