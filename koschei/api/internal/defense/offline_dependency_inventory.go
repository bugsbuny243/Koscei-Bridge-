package defense

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	OfflineDependencyInventorySchemaVersion = "koschei-offline-dependency-inventory-v1"
	OfflineDependencyPolicyVersion          = "koschei-image-vendor-v1"
	OfflineDependencyPackageName            = "litesvm"
	OfflineDependencyPackageVersion         = "0.6.1"
	OfflineDependencyRootPath               = "/opt/koschei/offline-deps"
	OfflineDependencyVendorPath             = OfflineDependencyRootPath + "/vendor"
	OfflineDependencyCargoConfigPath        = OfflineDependencyRootPath + "/cargo-config.toml"
	OfflineDependencyInventoryPath          = OfflineDependencyRootPath + "/inventory.json"
)

const OfflineDependencyCargoConfig = `[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "/opt/koschei/offline-deps/vendor"

[net]
offline = true
`

var offlineDependencyLiteSVMManifestPattern = regexp.MustCompile(`(?mi)^\s*litesvm\s*=\s*["']=0\.6\.1["']\s*$`)

const (
	DependencyInventoryUnavailable   = "dependency_inventory_unavailable"
	DependencyInventoryMalformed     = "dependency_inventory_malformed"
	DependencyInventoryPathEscape    = "dependency_inventory_path_escape"
	DependencyInventoryFileMissing   = "dependency_inventory_file_missing"
	DependencyInventoryFileMismatch  = "dependency_inventory_file_mismatch"
	DependencyInventoryHashMismatch  = "dependency_inventory_hash_mismatch"
	DependencyLockMismatch           = "dependency_lock_mismatch"
	DependencyCargoConfigMismatch    = "dependency_cargo_config_mismatch"
	DependencyLiteSVMVersionMismatch = "dependency_litesvm_version_mismatch"
)

type OfflineDependencyInventoryFile struct {
	Path        string `json:"path"`
	SizeBytes   int64  `json:"size_bytes"`
	ContentHash string `json:"content_hash"`
}

type OfflineDependencyInventory struct {
	SchemaVersion        string                           `json:"schema_version"`
	PolicyVersion        string                           `json:"policy_version"`
	CargoManifestHash    string                           `json:"cargo_manifest_hash"`
	CargoLockHash        string                           `json:"cargo_lock_hash"`
	CargoConfigHash      string                           `json:"cargo_config_hash"`
	PackageName          string                           `json:"package_name"`
	PackageVersion       string                           `json:"package_version"`
	Files                []OfflineDependencyInventoryFile `json:"files"`
	FileCount            int                              `json:"file_count"`
	TotalBytes           int64                            `json:"total_bytes"`
	VendorTreeHash       string                           `json:"vendor_tree_hash"`
	NetworkAccess        bool                             `json:"network_access"`
	DependencyResolution bool                             `json:"dependency_resolution"`
	InventoryHash        string                           `json:"inventory_hash"`
}

type offlineDependencyInventoryIdentity struct {
	SchemaVersion        string                           `json:"schema_version"`
	PolicyVersion        string                           `json:"policy_version"`
	CargoManifestHash    string                           `json:"cargo_manifest_hash"`
	CargoLockHash        string                           `json:"cargo_lock_hash"`
	CargoConfigHash      string                           `json:"cargo_config_hash"`
	PackageName          string                           `json:"package_name"`
	PackageVersion       string                           `json:"package_version"`
	Files                []OfflineDependencyInventoryFile `json:"files"`
	FileCount            int                              `json:"file_count"`
	TotalBytes           int64                            `json:"total_bytes"`
	VendorTreeHash       string                           `json:"vendor_tree_hash"`
	NetworkAccess        bool                             `json:"network_access"`
	DependencyResolution bool                             `json:"dependency_resolution"`
}

func BuildOfflineDependencyInventory(vendorRoot string, cargoManifest, cargoLock, cargoConfig []byte) (OfflineDependencyInventory, error) {
	if err := validateOfflineDependencyInputs(cargoManifest, cargoLock, cargoConfig); err != nil {
		return OfflineDependencyInventory{}, err
	}
	files, totalBytes, err := collectOfflineDependencyFiles(vendorRoot)
	if err != nil {
		return OfflineDependencyInventory{}, err
	}
	inventory := OfflineDependencyInventory{
		SchemaVersion:        OfflineDependencyInventorySchemaVersion,
		PolicyVersion:        OfflineDependencyPolicyVersion,
		CargoManifestHash:    offlineDependencyDigest(cargoManifest),
		CargoLockHash:        offlineDependencyDigest(cargoLock),
		CargoConfigHash:      offlineDependencyDigest(cargoConfig),
		PackageName:          OfflineDependencyPackageName,
		PackageVersion:       OfflineDependencyPackageVersion,
		Files:                files,
		FileCount:            len(files),
		TotalBytes:           totalBytes,
		VendorTreeHash:       offlineDependencyJSONDigest(files),
		NetworkAccess:        false,
		DependencyResolution: false,
	}
	inventory.InventoryHash = offlineDependencyJSONDigest(inventory.identity())
	if err := ValidateOfflineDependencyInventory(inventory); err != nil {
		return OfflineDependencyInventory{}, err
	}
	return inventory, nil
}

func MarshalOfflineDependencyInventory(inventory OfflineDependencyInventory) ([]byte, error) {
	if err := ValidateOfflineDependencyInventory(inventory); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", DependencyInventoryMalformed, err)
	}
	return append(encoded, '\n'), nil
}

func ValidateOfflineDependencyInventory(inventory OfflineDependencyInventory) error {
	if inventory.SchemaVersion != OfflineDependencyInventorySchemaVersion || inventory.PolicyVersion != OfflineDependencyPolicyVersion {
		return errors.New(DependencyInventoryMalformed + ": unsupported schema or policy version")
	}
	if inventory.PackageName != OfflineDependencyPackageName || inventory.PackageVersion != OfflineDependencyPackageVersion {
		return errors.New(DependencyLiteSVMVersionMismatch + ": unexpected package identity")
	}
	if inventory.NetworkAccess || inventory.DependencyResolution {
		return errors.New(DependencyInventoryMalformed + ": runtime boundary must remain false")
	}
	for _, digest := range []string{inventory.CargoManifestHash, inventory.CargoLockHash, inventory.CargoConfigHash, inventory.VendorTreeHash, inventory.InventoryHash} {
		if !validOfflineDependencyDigest(digest) {
			return errors.New(DependencyInventoryMalformed + ": invalid SHA-256 evidence")
		}
	}
	if inventory.FileCount != len(inventory.Files) || inventory.FileCount <= 0 || inventory.TotalBytes < 0 {
		return errors.New(DependencyInventoryMalformed + ": invalid file totals")
	}
	seen := make(map[string]struct{}, len(inventory.Files))
	var totalBytes int64
	previous := ""
	for index, file := range inventory.Files {
		clean, err := canonicalOfflineDependencyPath(file.Path)
		if err != nil || clean != file.Path {
			return errors.New(DependencyInventoryPathEscape + ": non-canonical inventory path")
		}
		if _, exists := seen[file.Path]; exists {
			return errors.New(DependencyInventoryMalformed + ": duplicate inventory path")
		}
		seen[file.Path] = struct{}{}
		if index > 0 && previous >= file.Path {
			return errors.New(DependencyInventoryMalformed + ": file inventory is not strictly sorted")
		}
		previous = file.Path
		if file.SizeBytes < 0 || !validOfflineDependencyDigest(file.ContentHash) {
			return errors.New(DependencyInventoryMalformed + ": invalid file evidence")
		}
		totalBytes += file.SizeBytes
	}
	if totalBytes != inventory.TotalBytes {
		return errors.New(DependencyInventoryMalformed + ": total byte count mismatch")
	}
	if offlineDependencyJSONDigest(inventory.Files) != inventory.VendorTreeHash {
		return errors.New(DependencyInventoryHashMismatch + ": vendor tree identity mismatch")
	}
	if offlineDependencyJSONDigest(inventory.identity()) != inventory.InventoryHash {
		return errors.New(DependencyInventoryHashMismatch + ": inventory identity mismatch")
	}
	return nil
}

func VerifyOfflineDependencyInventory(vendorRoot string, cargoManifest, cargoLock, cargoConfig []byte, expected OfflineDependencyInventory) error {
	if err := ValidateOfflineDependencyInventory(expected); err != nil {
		return err
	}
	if offlineDependencyDigest(cargoManifest) != expected.CargoManifestHash {
		return errors.New(DependencyInventoryHashMismatch + ": Cargo.toml bytes changed")
	}
	if offlineDependencyDigest(cargoLock) != expected.CargoLockHash {
		return errors.New(DependencyLockMismatch + ": Cargo.lock bytes changed")
	}
	if offlineDependencyDigest(cargoConfig) != expected.CargoConfigHash || string(cargoConfig) != OfflineDependencyCargoConfig {
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
	actual, err := BuildOfflineDependencyInventory(vendorRoot, cargoManifest, cargoLock, cargoConfig)
	if err != nil {
		return err
	}
	if actual.InventoryHash != expected.InventoryHash {
		return errors.New(DependencyInventoryHashMismatch + ": canonical inventory changed")
	}
	return nil
}

func validateOfflineDependencyInputs(cargoManifest, cargoLock, cargoConfig []byte) error {
	if len(cargoManifest) == 0 || len(cargoLock) == 0 {
		return errors.New(DependencyInventoryMalformed + ": Cargo.toml and Cargo.lock are required")
	}
	if string(cargoConfig) != OfflineDependencyCargoConfig {
		return errors.New(DependencyCargoConfigMismatch + ": fixed Cargo configuration is required")
	}
	manifestText := string(cargoManifest)
	lockText := string(cargoLock)
	if err := validateOfflineCargoMaterialization(manifestText, lockText); err != nil {
		return fmt.Errorf("%s: %w", DependencyLiteSVMVersionMismatch, err)
	}
	if !offlineDependencyLiteSVMManifestPattern.MatchString(manifestText) || !offlineDependencyLockPinsLiteSVM(lockText) {
		return errors.New(DependencyLiteSVMVersionMismatch + ": litesvm must be pinned exactly to 0.6.1 in Cargo.toml and Cargo.lock")
	}
	return nil
}

func offlineDependencyLockPinsLiteSVM(cargoLock string) bool {
	for _, section := range strings.Split(cargoLock, "[[package]]") {
		if strings.Contains(section, `name = "litesvm"`) && strings.Contains(section, `version = "0.6.1"`) {
			return true
		}
	}
	return false
}

func collectOfflineDependencyFiles(vendorRoot string) ([]OfflineDependencyInventoryFile, int64, error) {
	vendorRoot = filepath.Clean(strings.TrimSpace(vendorRoot))
	if vendorRoot == "" || vendorRoot == "." || !filepath.IsAbs(vendorRoot) {
		return nil, 0, errors.New(DependencyInventoryUnavailable + ": vendor root must be absolute")
	}
	rootInfo, err := os.Lstat(vendorRoot)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", DependencyInventoryUnavailable, err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New(DependencyInventoryPathEscape + ": vendor root must be a real directory")
	}
	files := []OfflineDependencyInventoryFile{}
	var totalBytes int64
	err = filepath.WalkDir(vendorRoot, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == vendorRoot {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New(DependencyInventoryPathEscape + ": symlink rejected")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New(DependencyInventoryMalformed + ": non-regular vendor entry")
		}
		relative, err := filepath.Rel(vendorRoot, current)
		if err != nil {
			return err
		}
		relative, err = canonicalOfflineDependencyPath(filepath.ToSlash(relative))
		if err != nil {
			return err
		}
		content, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		if int64(len(content)) != info.Size() {
			return errors.New(DependencyInventoryFileMismatch + ": file changed while hashing")
		}
		files = append(files, OfflineDependencyInventoryFile{Path: relative, SizeBytes: int64(len(content)), ContentHash: offlineDependencyDigest(content)})
		totalBytes += int64(len(content))
		return nil
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "dependency_") {
			return nil, 0, err
		}
		return nil, 0, fmt.Errorf("%s: %w", DependencyInventoryUnavailable, err)
	}
	if len(files) == 0 {
		return nil, 0, errors.New(DependencyInventoryUnavailable + ": vendor tree is empty")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, totalBytes, nil
}

func compareOfflineDependencyFiles(expected, actual []OfflineDependencyInventoryFile) error {
	expectedByPath := make(map[string]OfflineDependencyInventoryFile, len(expected))
	for _, file := range expected {
		expectedByPath[file.Path] = file
	}
	actualByPath := make(map[string]OfflineDependencyInventoryFile, len(actual))
	for _, file := range actual {
		actualByPath[file.Path] = file
	}
	for path, file := range expectedByPath {
		actualFile, ok := actualByPath[path]
		if !ok {
			return fmt.Errorf("%s: %s", DependencyInventoryFileMissing, path)
		}
		if actualFile.SizeBytes != file.SizeBytes || actualFile.ContentHash != file.ContentHash {
			return fmt.Errorf("%s: %s", DependencyInventoryFileMismatch, path)
		}
	}
	for path := range actualByPath {
		if _, ok := expectedByPath[path]; !ok {
			return fmt.Errorf("%s: unexpected %s", DependencyInventoryFileMismatch, path)
		}
	}
	return nil
}

func canonicalOfflineDependencyPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsRune(value, '\x00') || strings.Contains(value, "\\") || path.IsAbs(value) {
		return "", errors.New(DependencyInventoryPathEscape + ": invalid path")
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != value {
		return "", errors.New(DependencyInventoryPathEscape + ": invalid path")
	}
	return clean, nil
}

func (inventory OfflineDependencyInventory) identity() offlineDependencyInventoryIdentity {
	return offlineDependencyInventoryIdentity{
		SchemaVersion:        inventory.SchemaVersion,
		PolicyVersion:        inventory.PolicyVersion,
		CargoManifestHash:    inventory.CargoManifestHash,
		CargoLockHash:        inventory.CargoLockHash,
		CargoConfigHash:      inventory.CargoConfigHash,
		PackageName:          inventory.PackageName,
		PackageVersion:       inventory.PackageVersion,
		Files:                inventory.Files,
		FileCount:            inventory.FileCount,
		TotalBytes:           inventory.TotalBytes,
		VendorTreeHash:       inventory.VendorTreeHash,
		NetworkAccess:        inventory.NetworkAccess,
		DependencyResolution: inventory.DependencyResolution,
	}
}

func offlineDependencyDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func offlineDependencyJSONDigest(value any) string {
	encoded, _ := json.Marshal(value)
	return offlineDependencyDigest(encoded)
}

func validOfflineDependencyDigest(value string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	hexValue := strings.TrimPrefix(value, "sha256:")
	if hexValue != strings.ToLower(hexValue) {
		return false
	}
	_, err := hex.DecodeString(hexValue)
	return err == nil
}
