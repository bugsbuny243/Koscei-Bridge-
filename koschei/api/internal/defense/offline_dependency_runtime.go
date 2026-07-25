package defense

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type OfflineDependencyRuntimeAuthorization struct {
	InventoryRef         string `json:"inventory_ref"`
	InventoryHash        string `json:"inventory_hash"`
	VendorTreeHash       string `json:"vendor_tree_hash"`
	CargoManifestHash    string `json:"cargo_manifest_hash"`
	CargoLockHash        string `json:"cargo_lock_hash"`
	CargoConfigHash      string `json:"cargo_config_hash"`
	PackageName          string `json:"package_name"`
	PackageVersion       string `json:"package_version"`
	FileCount            int    `json:"file_count"`
	TotalBytes           int64  `json:"total_bytes"`
	WorkerID             string `json:"worker_id"`
	WorkerImageDigest    string `json:"worker_image_digest"`
	InventoryPath        string `json:"inventory_path"`
	VendorPath           string `json:"vendor_path"`
	CargoConfigPath      string `json:"cargo_config_path"`
	NetworkAccess        bool   `json:"network_access"`
	DependencyResolution bool   `json:"dependency_resolution"`
	VerdictAuthority     bool   `json:"verdict_authority"`
}

// AuthorizeOfflineDependencyRuntime re-hashes the immutable image-baked vendor
// store and binds it to one Phase 12B materialization before any source launch.
func AuthorizeOfflineDependencyRuntime(ctx context.Context, db *sql.DB, workerID, workerImageDigest, materializationRef string) (OfflineDependencyRuntimeAuthorization, error) {
	return authorizeOfflineDependencyRuntimeAtRoot(ctx, db, workerID, workerImageDigest, materializationRef, OfflineDependencyRootPath)
}

func authorizeOfflineDependencyRuntimeAtRoot(ctx context.Context, db *sql.DB, workerID, workerImageDigest, materializationRef, root string) (OfflineDependencyRuntimeAuthorization, error) {
	if db == nil {
		return OfflineDependencyRuntimeAuthorization{}, errors.New("database unavailable")
	}
	workerID = strings.TrimSpace(workerID)
	workerImageDigest = normalizeDefenseSHA256Digest(workerImageDigest)
	materializationRef = strings.TrimSpace(materializationRef)
	if workerID == "" || workerImageDigest == "" || materializationRef == "" {
		return OfflineDependencyRuntimeAuthorization{}, errors.New("offline dependency worker, image and materialization identity are required")
	}
	root, err := validateOfflineDependencyRuntimeRoot(root)
	if err != nil {
		return OfflineDependencyRuntimeAuthorization{}, err
	}
	inventoryPath := filepath.Join(root, "inventory.json")
	vendorPath := filepath.Join(root, "vendor")
	cargoConfigPath := filepath.Join(root, "cargo-config.toml")

	inventoryRaw, err := readOfflineDependencyRegularFile(inventoryPath)
	if err != nil {
		return OfflineDependencyRuntimeAuthorization{}, fmt.Errorf("%s: %w", DependencyInventoryUnavailable, err)
	}
	inventory, err := decodeCanonicalOfflineDependencyInventory(inventoryRaw)
	if err != nil {
		return OfflineDependencyRuntimeAuthorization{}, err
	}
	cargoConfig, err := readOfflineDependencyRegularFile(cargoConfigPath)
	if err != nil {
		return OfflineDependencyRuntimeAuthorization{}, fmt.Errorf("%s: %w", DependencyCargoConfigMismatch, err)
	}

	materialization, err := LoadHarnessMaterialization(ctx, db, materializationRef)
	if err != nil {
		return OfflineDependencyRuntimeAuthorization{}, errors.New("offline dependency materialization not found")
	}
	if materialization.Status != "ready" || materialization.Engine != HarnessEngineLiteSVM || materialization.NetworkAccess || materialization.DependencyResolution || materialization.SourceExecuted || materialization.HarnessExecuted || materialization.MainnetTransactionSent || materialization.VerdictAuthority {
		return OfflineDependencyRuntimeAuthorization{}, errors.New("offline dependency materialization is not a ready non-executed LiteSVM input")
	}
	if materialization.CargoManifestHash != inventory.CargoManifestHash {
		return OfflineDependencyRuntimeAuthorization{}, errors.New(DependencyInventoryHashMismatch + ": materialized Cargo.toml is not approved by the inventory")
	}
	if materialization.CargoLockHash != inventory.CargoLockHash {
		return OfflineDependencyRuntimeAuthorization{}, errors.New(DependencyLockMismatch + ": materialized Cargo.lock is not approved by the inventory")
	}
	artifact, err := LoadArtifact(ctx, db, materialization.MaterializedArtifactRef)
	if err != nil {
		return OfflineDependencyRuntimeAuthorization{}, errors.New("offline dependency materialized artifact not found")
	}
	bundle, err := decodeSourceBundle(artifact.Content)
	if err != nil {
		return OfflineDependencyRuntimeAuthorization{}, err
	}
	cargoManifest, manifestOK := bundle["Cargo.toml"]
	cargoLock, lockOK := bundle["Cargo.lock"]
	if !manifestOK || !lockOK {
		return OfflineDependencyRuntimeAuthorization{}, errors.New(DependencyInventoryMalformed + ": materialized Cargo inputs are missing")
	}
	if hashMaterializationBytes([]byte(cargoManifest)) != materialization.CargoManifestHash || hashMaterializationBytes([]byte(cargoLock)) != materialization.CargoLockHash {
		return OfflineDependencyRuntimeAuthorization{}, errors.New(DependencyInventoryHashMismatch + ": materialized Cargo bytes changed")
	}
	if err := VerifyOfflineDependencyInventory(vendorPath, []byte(cargoManifest), []byte(cargoLock), cargoConfig, inventory); err != nil {
		return OfflineDependencyRuntimeAuthorization{}, err
	}

	evidence, err := loadAuthorizedOfflineDependencyEvidence(ctx, db, workerID, workerImageDigest, inventory.InventoryHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OfflineDependencyRuntimeAuthorization{}, errors.New(DependencyInventoryUnavailable + ": immutable worker inventory evidence is not authorized")
		}
		return OfflineDependencyRuntimeAuthorization{}, err
	}
	if err := validateOfflineDependencyEvidenceBinding(evidence, inventory); err != nil {
		return OfflineDependencyRuntimeAuthorization{}, err
	}
	return OfflineDependencyRuntimeAuthorization{
		InventoryRef:         evidence.InventoryRef,
		InventoryHash:        inventory.InventoryHash,
		VendorTreeHash:       inventory.VendorTreeHash,
		CargoManifestHash:    inventory.CargoManifestHash,
		CargoLockHash:        inventory.CargoLockHash,
		CargoConfigHash:      inventory.CargoConfigHash,
		PackageName:          inventory.PackageName,
		PackageVersion:       inventory.PackageVersion,
		FileCount:            inventory.FileCount,
		TotalBytes:           inventory.TotalBytes,
		WorkerID:             workerID,
		WorkerImageDigest:    workerImageDigest,
		InventoryPath:        inventoryPath,
		VendorPath:           vendorPath,
		CargoConfigPath:      cargoConfigPath,
		NetworkAccess:        false,
		DependencyResolution: false,
		VerdictAuthority:     false,
	}, nil
}

func loadAuthorizedOfflineDependencyEvidence(ctx context.Context, db *sql.DB, workerID, workerImageDigest, inventoryHash string) (OfflineDependencyInventoryEvidence, error) {
	var inventoryRef string
	err := db.QueryRowContext(ctx, `SELECT inventory_ref FROM defense_offline_dependency_inventories
		WHERE worker_id=$1 AND worker_image_digest=$2 AND inventory_hash=$3 AND evidence_status='verified'
		  AND network_access=false AND dependency_resolution=false AND verdict_authority=false
		ORDER BY observed_at DESC LIMIT 1`, workerID, workerImageDigest, inventoryHash).Scan(&inventoryRef)
	if err != nil {
		return OfflineDependencyInventoryEvidence{}, err
	}
	return LoadOfflineDependencyInventoryEvidence(ctx, db, inventoryRef)
}

func validateOfflineDependencyEvidenceBinding(evidence OfflineDependencyInventoryEvidence, inventory OfflineDependencyInventory) error {
	if evidence.EvidenceStatus != "verified" || evidence.InventoryPath != OfflineDependencyInventoryPath || evidence.VendorPath != OfflineDependencyVendorPath || evidence.CargoConfigPath != OfflineDependencyCargoConfigPath {
		return errors.New(DependencyInventoryMalformed + ": immutable inventory path evidence is invalid")
	}
	if evidence.InventoryHash != inventory.InventoryHash || evidence.VendorTreeHash != inventory.VendorTreeHash || evidence.CargoManifestHash != inventory.CargoManifestHash || evidence.CargoLockHash != inventory.CargoLockHash || evidence.CargoConfigHash != inventory.CargoConfigHash || evidence.PackageName != inventory.PackageName || evidence.PackageVersion != inventory.PackageVersion || evidence.FileCount != inventory.FileCount || evidence.TotalBytes != inventory.TotalBytes {
		return errors.New(DependencyInventoryHashMismatch + ": immutable inventory evidence does not match the live store")
	}
	if evidence.NetworkAccess || evidence.DependencyResolution || evidence.VerdictAuthority {
		return errors.New(DependencyInventoryMalformed + ": immutable inventory evidence crossed a Phase 12C boundary")
	}
	return nil
}

func validateOfflineDependencyRuntimeRoot(value string) (string, error) {
	value = filepath.Clean(strings.TrimSpace(value))
	if value == "" || value == "." || value == string(os.PathSeparator) || !filepath.IsAbs(value) {
		return "", errors.New(DependencyInventoryUnavailable + ": dependency root must be an absolute directory")
	}
	info, err := os.Lstat(value)
	if err != nil {
		return "", fmt.Errorf("%s: %w", DependencyInventoryUnavailable, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New(DependencyInventoryPathEscape + ": dependency root must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil || filepath.Clean(resolved) != value {
		return "", errors.New(DependencyInventoryPathEscape + ": dependency root must not traverse symlinks")
	}
	return value, nil
}

func readOfflineDependencyRegularFile(filename string) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("offline dependency evidence path is not a regular file")
	}
	return os.ReadFile(filename)
}

func decodeCanonicalOfflineDependencyInventory(raw []byte) (OfflineDependencyInventory, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var inventory OfflineDependencyInventory
	if err := decoder.Decode(&inventory); err != nil {
		return OfflineDependencyInventory{}, fmt.Errorf("%s: %w", DependencyInventoryMalformed, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OfflineDependencyInventory{}, errors.New(DependencyInventoryMalformed + ": trailing inventory data")
	}
	if err := ValidateOfflineDependencyInventory(inventory); err != nil {
		return OfflineDependencyInventory{}, err
	}
	canonical, err := MarshalOfflineDependencyInventory(inventory)
	if err != nil {
		return OfflineDependencyInventory{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return OfflineDependencyInventory{}, errors.New(DependencyInventoryMalformed + ": inventory JSON is not canonical")
	}
	return inventory, nil
}
