package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const OfflineDependencyInventoryEvidenceVersion = "v1.0.0"

type OfflineDependencyInventoryEvidence struct {
	InventoryRef         string                           `json:"inventory_ref"`
	InventoryVersion     string                           `json:"inventory_version"`
	WorkerID             string                           `json:"worker_id"`
	WorkerImageDigest    string                           `json:"worker_image_digest"`
	InventoryPath        string                           `json:"inventory_path"`
	VendorPath           string                           `json:"vendor_path"`
	CargoConfigPath      string                           `json:"cargo_config_path"`
	CargoManifestHash    string                           `json:"cargo_manifest_hash"`
	CargoLockHash        string                           `json:"cargo_lock_hash"`
	CargoConfigHash      string                           `json:"cargo_config_hash"`
	PackageName          string                           `json:"package_name"`
	PackageVersion       string                           `json:"package_version"`
	FileManifest         []OfflineDependencyInventoryFile `json:"file_manifest"`
	FileCount            int                              `json:"file_count"`
	TotalBytes           int64                            `json:"total_bytes"`
	VendorTreeHash       string                           `json:"vendor_tree_hash"`
	InventoryHash        string                           `json:"inventory_hash"`
	EvidenceStatus       string                           `json:"evidence_status"`
	Limitations          []string                         `json:"limitations"`
	NetworkAccess        bool                             `json:"network_access"`
	DependencyResolution bool                             `json:"dependency_resolution"`
	VerdictAuthority     bool                             `json:"verdict_authority"`
	ObservedAt           time.Time                        `json:"observed_at"`
	CreatedAt            time.Time                        `json:"created_at"`
}

func PersistOfflineDependencyInventoryEvidence(ctx context.Context, db *sql.DB, workerID, workerImageDigest string, inventory OfflineDependencyInventory, observedAt time.Time, limitations []string) (OfflineDependencyInventoryEvidence, error) {
	if db == nil {
		return OfflineDependencyInventoryEvidence{}, errors.New("database unavailable")
	}
	workerID = strings.TrimSpace(workerID)
	workerImageDigest = normalizeDefenseSHA256Digest(workerImageDigest)
	if workerID == "" || workerImageDigest == "" {
		return OfflineDependencyInventoryEvidence{}, errors.New("offline dependency worker identity and immutable image digest are required")
	}
	if err := ValidateOfflineDependencyInventory(inventory); err != nil {
		return OfflineDependencyInventoryEvidence{}, err
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	} else {
		observedAt = observedAt.UTC()
	}
	limitations = uniqueStrings(limitations)
	identity := map[string]any{
		"inventory_version":   OfflineDependencyInventoryEvidenceVersion,
		"worker_id":           workerID,
		"worker_image_digest": workerImageDigest,
		"inventory_hash":      inventory.InventoryHash,
	}
	inventoryRef := prefixedID("KODI1-", identity)
	manifestRaw, _ := json.Marshal(inventory.Files)
	limitationsRaw, _ := json.Marshal(limitations)
	_, err := db.ExecContext(ctx, `INSERT INTO defense_offline_dependency_inventories
		(inventory_ref,inventory_version,worker_id,worker_image_digest,inventory_path,vendor_path,cargo_config_path,
		 cargo_manifest_hash,cargo_lock_hash,cargo_config_hash,package_name,package_version,file_manifest,file_count,
		 total_bytes,vendor_tree_hash,inventory_hash,evidence_status,limitations,network_access,dependency_resolution,
		 verdict_authority,observed_at,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,'verified',$18::jsonb,
		 false,false,false,$19,'defense-worker')
		ON CONFLICT(inventory_ref) DO NOTHING`,
		inventoryRef, OfflineDependencyInventoryEvidenceVersion, workerID, workerImageDigest,
		OfflineDependencyInventoryPath, OfflineDependencyVendorPath, OfflineDependencyCargoConfigPath,
		inventory.CargoManifestHash, inventory.CargoLockHash, inventory.CargoConfigHash,
		inventory.PackageName, inventory.PackageVersion, string(manifestRaw), inventory.FileCount,
		inventory.TotalBytes, inventory.VendorTreeHash, inventory.InventoryHash, string(limitationsRaw), observedAt)
	if err != nil {
		return OfflineDependencyInventoryEvidence{}, err
	}
	return LoadOfflineDependencyInventoryEvidence(ctx, db, inventoryRef)
}

func LoadOfflineDependencyInventoryEvidence(ctx context.Context, db *sql.DB, inventoryRef string) (OfflineDependencyInventoryEvidence, error) {
	if db == nil {
		return OfflineDependencyInventoryEvidence{}, errors.New("database unavailable")
	}
	var item OfflineDependencyInventoryEvidence
	var manifestRaw, limitationsRaw []byte
	err := db.QueryRowContext(ctx, `SELECT inventory_ref,inventory_version,worker_id,worker_image_digest,inventory_path,
		vendor_path,cargo_config_path,cargo_manifest_hash,cargo_lock_hash,cargo_config_hash,package_name,package_version,
		file_manifest,file_count,total_bytes,vendor_tree_hash,inventory_hash,evidence_status,limitations,network_access,
		dependency_resolution,verdict_authority,observed_at,created_at
		FROM defense_offline_dependency_inventories WHERE inventory_ref=$1`, strings.TrimSpace(inventoryRef)).Scan(
		&item.InventoryRef, &item.InventoryVersion, &item.WorkerID, &item.WorkerImageDigest, &item.InventoryPath,
		&item.VendorPath, &item.CargoConfigPath, &item.CargoManifestHash, &item.CargoLockHash, &item.CargoConfigHash,
		&item.PackageName, &item.PackageVersion, &manifestRaw, &item.FileCount, &item.TotalBytes, &item.VendorTreeHash,
		&item.InventoryHash, &item.EvidenceStatus, &limitationsRaw, &item.NetworkAccess, &item.DependencyResolution,
		&item.VerdictAuthority, &item.ObservedAt, &item.CreatedAt)
	if err != nil {
		return OfflineDependencyInventoryEvidence{}, err
	}
	_ = json.Unmarshal(manifestRaw, &item.FileManifest)
	_ = json.Unmarshal(limitationsRaw, &item.Limitations)
	return item, nil
}
