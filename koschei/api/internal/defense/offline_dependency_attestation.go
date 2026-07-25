package defense

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// AttestOfflineDependencyRuntimeStore recomputes the image-baked dependency
// store and persists immutable worker/image evidence. It does not execute source.
func AttestOfflineDependencyRuntimeStore(ctx context.Context, db *sql.DB, workerID, workerImageDigest string) (OfflineDependencyInventoryEvidence, error) {
	return attestOfflineDependencyRuntimeStoreAtRoot(ctx, db, workerID, workerImageDigest, OfflineDependencyRootPath)
}

func attestOfflineDependencyRuntimeStoreAtRoot(ctx context.Context, db *sql.DB, workerID, workerImageDigest, root string) (OfflineDependencyInventoryEvidence, error) {
	if db == nil {
		return OfflineDependencyInventoryEvidence{}, errors.New("database unavailable")
	}
	root, err := validateOfflineDependencyRuntimeRoot(root)
	if err != nil {
		return OfflineDependencyInventoryEvidence{}, err
	}
	inventoryRaw, err := readOfflineDependencyRegularFile(filepath.Join(root, "inventory.json"))
	if err != nil {
		return OfflineDependencyInventoryEvidence{}, fmt.Errorf("%s: %w", DependencyInventoryUnavailable, err)
	}
	inventory, err := decodeCanonicalOfflineDependencyInventory(inventoryRaw)
	if err != nil {
		return OfflineDependencyInventoryEvidence{}, err
	}
	cargoConfig, err := readOfflineDependencyRegularFile(filepath.Join(root, "cargo-config.toml"))
	if err != nil {
		return OfflineDependencyInventoryEvidence{}, fmt.Errorf("%s: %w", DependencyCargoConfigMismatch, err)
	}
	if err := VerifyOfflineDependencyStoreContents(filepath.Join(root, "vendor"), cargoConfig, inventory); err != nil {
		return OfflineDependencyInventoryEvidence{}, err
	}
	return PersistOfflineDependencyInventoryEvidence(ctx, db, workerID, workerImageDigest, inventory, time.Now().UTC(), []string{
		"The inventory attests immutable image content only; external no-egress and resource ceilings require separate deployment evidence.",
		"No imported source, harness instruction, wallet operation, RPC request or transaction was executed.",
	})
}

func VerifyOfflineDependencyStoreContents(vendorRoot string, cargoConfig []byte, expected OfflineDependencyInventory) error {
	if err := ValidateOfflineDependencyInventory(expected); err != nil {
		return err
	}
	if string(cargoConfig) != OfflineDependencyCargoConfig || offlineDependencyDigest(cargoConfig) != expected.CargoConfigHash {
		return errors.New(DependencyCargoConfigMismatch + ": Cargo source replacement changed")
	}
	actualFiles, actualTotal, err := collectOfflineDependencyFiles(vendorRoot)
	if err != nil {
		return err
	}
	if err := compareOfflineDependencyFiles(expected.Files, actualFiles); err != nil {
		return err
	}
	if actualTotal != expected.TotalBytes || offlineDependencyJSONDigest(actualFiles) != expected.VendorTreeHash {
		return errors.New(DependencyInventoryHashMismatch + ": vendor tree identity changed")
	}
	return nil
}
