package defense

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	HarnessMaterializationVersion = "v1.0.0"
	HarnessMaterializationSchema  = "koschei-harness-materialization-v1"
	materializationManifestPath   = "koschei/materialization.json"
)

type HarnessMaterializationInput struct {
	ProfileRef string `json:"profile_ref"`
}

type HarnessMaterializedFile struct {
	Path        string `json:"path"`
	SizeBytes   int    `json:"size_bytes"`
	ContentHash string `json:"content_hash"`
	Generated   bool   `json:"generated"`
}

type HarnessMaterialization struct {
	MaterializationRef       string                    `json:"materialization_ref"`
	MaterializationVersion   string                    `json:"materialization_version"`
	ProfileRef               string                    `json:"profile_ref"`
	SourceHarnessArtifactRef string                    `json:"source_harness_artifact_ref"`
	MaterializedArtifactRef  string                    `json:"materialized_artifact_ref"`
	ProgramID                string                    `json:"program_id"`
	Network                  string                    `json:"network"`
	Engine                   string                    `json:"engine"`
	Status                   string                    `json:"status"`
	FileManifest             []HarnessMaterializedFile `json:"file_manifest"`
	FileCount                int                       `json:"file_count"`
	TotalBytes               int                       `json:"total_bytes"`
	CargoManifestHash        string                    `json:"cargo_manifest_hash"`
	CargoLockHash            string                    `json:"cargo_lock_hash"`
	MaterializedBundleHash   string                    `json:"materialized_bundle_hash"`
	EvidenceRefs             []string                  `json:"evidence_refs"`
	Limitations              []string                  `json:"limitations"`
	NetworkAccess            bool                      `json:"network_access"`
	DependencyResolution     bool                      `json:"dependency_resolution"`
	SourceExecuted           bool                      `json:"source_executed"`
	HarnessExecuted          bool                      `json:"harness_executed"`
	MainnetTransactionSent   bool                      `json:"mainnet_transaction_sent"`
	MaterializationHash      string                    `json:"materialization_hash"`
	VerdictAuthority         bool                      `json:"verdict_authority"`
	CreatedAt                time.Time                 `json:"created_at"`
}

type harnessMaterializationManifest struct {
	SchemaVersion             string                    `json:"schema_version"`
	MaterializationVersion    string                    `json:"materialization_version"`
	ProfileRef                string                    `json:"profile_ref"`
	ProfileHash               string                    `json:"profile_hash"`
	SourceHarnessArtifactRef  string                    `json:"source_harness_artifact_ref"`
	SourceHarnessArtifactHash string                    `json:"source_harness_artifact_hash"`
	ProgramID                 string                    `json:"program_id"`
	Network                   string                    `json:"network"`
	Engine                    string                    `json:"engine"`
	SourceFiles               []HarnessMaterializedFile `json:"source_files"`
	CargoManifestHash         string                    `json:"cargo_manifest_hash"`
	CargoLockHash             string                    `json:"cargo_lock_hash"`
	CommandPolicy             map[string]any            `json:"command_policy"`
	NetworkAccess             bool                      `json:"network_access"`
	DependencyResolution      bool                      `json:"dependency_resolution"`
	SourceExecuted            bool                      `json:"source_executed"`
	HarnessExecuted           bool                      `json:"harness_executed"`
	MainnetTransactionSent    bool                      `json:"mainnet_transaction_sent"`
	VerdictAuthority          bool                      `json:"verdict_authority"`
}

var (
	cargoLockVersionPattern    = regexp.MustCompile(`(?m)^version\s*=\s*[34]\s*$`)
	cargoLockPackagePattern    = regexp.MustCompile(`(?m)^\[\[package\]\]\s*$`)
	liteSVMDependencyPattern   = regexp.MustCompile(`(?mi)^\s*litesvm\s*=\s*`)
	liteSVMLockPattern         = regexp.MustCompile(`(?m)^name\s*=\s*"litesvm"\s*$`)
	cargoPathDependencyPattern = regexp.MustCompile(`(?mi)\bpath\s*=\s*["']([^"']+)["']`)
	cargoGitDependencyPattern  = regexp.MustCompile(`(?mi)\bgit\s*=\s*["']`)
)

// CreateHarnessMaterialization deterministically normalizes one immutable,
// owner-prepared harness bundle into a second immutable source-bundle artifact.
// It does not resolve dependencies, compile source, execute a harness or enqueue
// a worker job.
func CreateHarnessMaterialization(ctx context.Context, db *sql.DB, input HarnessMaterializationInput) (HarnessMaterialization, error) {
	if db == nil {
		return HarnessMaterialization{}, errors.New("database unavailable")
	}
	input.ProfileRef = strings.TrimSpace(input.ProfileRef)
	if input.ProfileRef == "" {
		return HarnessMaterialization{}, errors.New("profile_ref is required")
	}
	profile, err := LoadHarnessExecutionProfile(ctx, db, input.ProfileRef)
	if err != nil {
		return HarnessMaterialization{}, err
	}
	if profile.ReadinessStatus != "ready" || !profile.ExecutionAllowed {
		return HarnessMaterialization{}, errors.New("harness execution profile is blocked")
	}
	if profile.Engine != HarnessEngineLiteSVM {
		return HarnessMaterialization{}, errors.New("Phase 12B materialization currently supports litesvm profiles only")
	}

	sourceArtifact, err := LoadArtifact(ctx, db, profile.HarnessArtifactRef)
	if err != nil {
		return HarnessMaterialization{}, errors.New("source harness artifact not found")
	}
	if sourceArtifact.ArtifactType != "source_bundle" || sourceArtifact.ProgramID != profile.ProgramID || sourceArtifact.Network != profile.Network {
		return HarnessMaterialization{}, errors.New("source harness artifact does not match the execution profile")
	}
	if strings.ToLower(harnessArtifactMetadataString(sourceArtifact.Metadata, "artifact_role")) != "harness" ||
		strings.TrimSpace(harnessArtifactMetadataString(sourceArtifact.Metadata, "harness_plan_ref")) != profile.PlanRef {
		return HarnessMaterialization{}, errors.New("source harness artifact metadata does not match the execution profile")
	}

	bundle, err := decodeSourceBundle(sourceArtifact.Content)
	if err != nil {
		return HarnessMaterialization{}, err
	}
	normalizedBundle, fileManifest, cargoManifestHash, cargoLockHash, err := normalizeHarnessBundle(bundle, profile, sourceArtifact)
	if err != nil {
		return HarnessMaterialization{}, err
	}
	encodedBundle, err := json.Marshal(normalizedBundle)
	if err != nil {
		return HarnessMaterialization{}, errors.New("materialized harness bundle could not be encoded")
	}
	materializedArtifact, err := StoreArtifact(ctx, db, ArtifactInput{
		ProgramID:        profile.ProgramID,
		Network:          profile.Network,
		ArtifactType:     "source_bundle",
		Framework:        "anchor",
		FrameworkVersion: sourceArtifact.FrameworkVersion,
		RuntimeVersion:   sourceArtifact.RuntimeVersion,
		ContentEncoding:  "json",
		Content:          string(encodedBundle),
		Metadata: map[string]any{
			"artifact_role":               "materialized_harness",
			"materialization_schema":      HarnessMaterializationSchema,
			"harness_profile_ref":         profile.ProfileRef,
			"harness_plan_ref":            profile.PlanRef,
			"source_harness_artifact_ref": sourceArtifact.ArtifactRef,
			"engine":                      profile.Engine,
			"network_access":              false,
			"dependency_resolution":       false,
			"source_executed":             false,
			"harness_executed":            false,
			"mainnet_transaction_sent":    false,
			"production_eligible":         false,
		},
		TrustLevel: "observed",
		Verified:   false,
		CreatedBy:  "owner",
	})
	if err != nil {
		return HarnessMaterialization{}, err
	}

	totalBytes := 0
	for _, file := range fileManifest {
		totalBytes += file.SizeBytes
	}
	limitations := []string{
		"Materialization validates and normalizes an owner-prepared harness bundle; it does not establish compilation or runtime correctness.",
		"Cargo dependencies were not downloaded, resolved or updated; the supplied Cargo.lock remains the immutable dependency boundary.",
		"No harness instruction, source program or transaction was executed.",
	}
	evidenceRefs := uniqueStrings([]string{
		"harness_execution_profile:" + profile.ProfileRef,
		"artifact:" + sourceArtifact.ArtifactRef,
		"artifact:" + materializedArtifact.ArtifactRef,
	})
	payload := map[string]any{
		"schema_version":               HarnessMaterializationSchema,
		"materialization_version":      HarnessMaterializationVersion,
		"profile_ref":                  profile.ProfileRef,
		"profile_hash":                 profile.ProfileHash,
		"source_harness_artifact_ref":  sourceArtifact.ArtifactRef,
		"source_harness_artifact_hash": sourceArtifact.ContentHash,
		"materialized_artifact_ref":    materializedArtifact.ArtifactRef,
		"materialized_bundle_hash":     materializedArtifact.ContentHash,
		"program_id":                   profile.ProgramID,
		"network":                      profile.Network,
		"engine":                       profile.Engine,
		"status":                       "ready",
		"file_manifest":                fileManifest,
		"file_count":                   len(fileManifest),
		"total_bytes":                  totalBytes,
		"cargo_manifest_hash":          cargoManifestHash,
		"cargo_lock_hash":              cargoLockHash,
		"evidence_refs":                evidenceRefs,
		"limitations":                  limitations,
		"network_access":               false,
		"dependency_resolution":        false,
		"source_executed":              false,
		"harness_executed":             false,
		"mainnet_transaction_sent":     false,
		"verdict_authority":            false,
	}
	materializationHash := hashJSON(payload)
	materializationRef := prefixedID("KHM1-", payload)
	fileManifestRaw, _ := json.Marshal(fileManifest)
	evidenceRaw, _ := json.Marshal(evidenceRefs)
	limitationsRaw, _ := json.Marshal(limitations)
	now := time.Now().UTC()
	_, err = db.ExecContext(ctx, `INSERT INTO defense_harness_materializations
		(materialization_ref,materialization_version,profile_ref,source_harness_artifact_ref,materialized_artifact_ref,
		 program_id,network,engine,status,file_manifest,file_count,total_bytes,cargo_manifest_hash,cargo_lock_hash,
		 materialized_bundle_hash,evidence_refs,limitations,network_access,dependency_resolution,source_executed,
		 harness_executed,mainnet_transaction_sent,materialization_hash,verdict_authority,created_by,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'ready',$9::jsonb,$10,$11,$12,$13,$14,$15::jsonb,$16::jsonb,
		 false,false,false,false,false,$17,false,'owner',$18)
		ON CONFLICT(materialization_ref) DO NOTHING`, materializationRef, HarnessMaterializationVersion, profile.ProfileRef,
		sourceArtifact.ArtifactRef, materializedArtifact.ArtifactRef, profile.ProgramID, profile.Network, profile.Engine,
		string(fileManifestRaw), len(fileManifest), totalBytes, cargoManifestHash, cargoLockHash, materializedArtifact.ContentHash,
		string(evidenceRaw), string(limitationsRaw), materializationHash, now)
	if err != nil {
		return HarnessMaterialization{}, err
	}
	return LoadHarnessMaterialization(ctx, db, materializationRef)
}

func normalizeHarnessBundle(bundle map[string]string, profile HarnessExecutionProfile, source Artifact) (map[string]string, []HarnessMaterializedFile, string, string, error) {
	if len(bundle) == 0 || len(bundle) > 200 {
		return nil, nil, "", "", errors.New("harness bundle must contain between 1 and 200 files")
	}
	if _, exists := bundle[materializationManifestPath]; exists {
		return nil, nil, "", "", errors.New("harness bundle uses the reserved materialization manifest path")
	}
	paths := make([]string, 0, len(bundle))
	for path := range bundle {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	normalized := make(map[string]string, len(bundle)+1)
	sourceManifest := make([]HarnessMaterializedFile, 0, len(bundle))
	totalBytes := 0
	hasRustTest := false
	cargoManifest := ""
	cargoLock := ""
	for _, path := range paths {
		clean, err := safeRelativePath(path)
		if err != nil {
			return nil, nil, "", "", err
		}
		content := normalizeMaterializedText(bundle[path])
		if strings.ContainsRune(content, '\x00') {
			return nil, nil, "", "", fmt.Errorf("harness file contains a NUL byte: %s", clean)
		}
		if len(content) > 300*1024 {
			return nil, nil, "", "", fmt.Errorf("harness file exceeds 300 KiB: %s", clean)
		}
		totalBytes += len(content)
		if totalBytes > maxArtifactBytes-64*1024 {
			return nil, nil, "", "", errors.New("normalized harness source exceeds the materialization size budget")
		}
		normalized[clean] = content
		sourceManifest = append(sourceManifest, HarnessMaterializedFile{Path: clean, SizeBytes: len(content), ContentHash: hashMaterializationBytes([]byte(content)), Generated: false})
		if clean == "Cargo.toml" {
			cargoManifest = content
		}
		if clean == "Cargo.lock" {
			cargoLock = content
		}
		if strings.HasPrefix(clean, "tests/") && strings.HasSuffix(strings.ToLower(clean), ".rs") {
			hasRustTest = true
		}
	}
	if cargoManifest == "" {
		return nil, nil, "", "", errors.New("harness bundle requires a root Cargo.toml")
	}
	if cargoLock == "" {
		return nil, nil, "", "", errors.New("harness bundle requires an immutable root Cargo.lock")
	}
	if !hasRustTest {
		return nil, nil, "", "", errors.New("LiteSVM harness bundle requires at least one tests/*.rs file")
	}
	if err := validateOfflineCargoMaterialization(cargoManifest, cargoLock); err != nil {
		return nil, nil, "", "", err
	}
	cargoManifestHash := hashMaterializationBytes([]byte(cargoManifest))
	cargoLockHash := hashMaterializationBytes([]byte(cargoLock))
	manifest := harnessMaterializationManifest{
		SchemaVersion:             HarnessMaterializationSchema,
		MaterializationVersion:    HarnessMaterializationVersion,
		ProfileRef:                profile.ProfileRef,
		ProfileHash:               profile.ProfileHash,
		SourceHarnessArtifactRef:  source.ArtifactRef,
		SourceHarnessArtifactHash: source.ContentHash,
		ProgramID:                 profile.ProgramID,
		Network:                   profile.Network,
		Engine:                    profile.Engine,
		SourceFiles:               sourceManifest,
		CargoManifestHash:         cargoManifestHash,
		CargoLockHash:             cargoLockHash,
		CommandPolicy:             profile.CommandPolicy,
		NetworkAccess:             false,
		DependencyResolution:      false,
		SourceExecuted:            false,
		HarnessExecuted:           false,
		MainnetTransactionSent:    false,
		VerdictAuthority:          false,
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, nil, "", "", errors.New("materialization manifest could not be encoded")
	}
	manifestContent := string(manifestRaw) + "\n"
	normalized[materializationManifestPath] = manifestContent

	outputPaths := make([]string, 0, len(normalized))
	for path := range normalized {
		outputPaths = append(outputPaths, path)
	}
	sort.Strings(outputPaths)
	outputManifest := make([]HarnessMaterializedFile, 0, len(outputPaths))
	for _, path := range outputPaths {
		content := normalized[path]
		outputManifest = append(outputManifest, HarnessMaterializedFile{
			Path:        path,
			SizeBytes:   len(content),
			ContentHash: hashMaterializationBytes([]byte(content)),
			Generated:   path == materializationManifestPath,
		})
	}
	return normalized, outputManifest, cargoManifestHash, cargoLockHash, nil
}

func validateOfflineCargoMaterialization(cargoManifest, cargoLock string) error {
	if cargoGitDependencyPattern.MatchString(cargoManifest) {
		return errors.New("git dependencies are not accepted in Phase 12B offline materialization")
	}
	for _, match := range cargoPathDependencyPattern.FindAllStringSubmatch(cargoManifest, -1) {
		candidate := filepath.ToSlash(strings.TrimSpace(match[1]))
		clean := filepath.Clean(candidate)
		if candidate == "" || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
			return errors.New("Cargo path dependency escapes the immutable harness bundle")
		}
	}
	if !liteSVMDependencyPattern.MatchString(cargoManifest) {
		return errors.New("Cargo.toml does not declare a LiteSVM dependency")
	}
	if !cargoLockVersionPattern.MatchString(cargoLock) || !cargoLockPackagePattern.MatchString(cargoLock) {
		return errors.New("Cargo.lock is missing a supported lock version or package records")
	}
	if !liteSVMLockPattern.MatchString(cargoLock) {
		return errors.New("Cargo.lock does not pin the LiteSVM package")
	}
	return nil
}

func normalizeMaterializedText(content string) string {
	content = strings.TrimPrefix(content, "\ufeff")
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content
}

func hashMaterializationBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func LoadHarnessMaterialization(ctx context.Context, db *sql.DB, ref string) (HarnessMaterialization, error) {
	if db == nil {
		return HarnessMaterialization{}, errors.New("database unavailable")
	}
	var item HarnessMaterialization
	var fileManifestRaw, evidenceRaw, limitationsRaw []byte
	err := db.QueryRowContext(ctx, `SELECT materialization_ref,materialization_version,profile_ref,source_harness_artifact_ref,
		materialized_artifact_ref,program_id,network,engine,status,file_manifest,file_count,total_bytes,cargo_manifest_hash,
		cargo_lock_hash,materialized_bundle_hash,evidence_refs,limitations,network_access,dependency_resolution,source_executed,
		harness_executed,mainnet_transaction_sent,materialization_hash,verdict_authority,created_at
		FROM defense_harness_materializations WHERE materialization_ref=$1`, strings.TrimSpace(ref)).Scan(
		&item.MaterializationRef, &item.MaterializationVersion, &item.ProfileRef, &item.SourceHarnessArtifactRef,
		&item.MaterializedArtifactRef, &item.ProgramID, &item.Network, &item.Engine, &item.Status, &fileManifestRaw,
		&item.FileCount, &item.TotalBytes, &item.CargoManifestHash, &item.CargoLockHash, &item.MaterializedBundleHash,
		&evidenceRaw, &limitationsRaw, &item.NetworkAccess, &item.DependencyResolution, &item.SourceExecuted,
		&item.HarnessExecuted, &item.MainnetTransactionSent, &item.MaterializationHash, &item.VerdictAuthority, &item.CreatedAt)
	if err != nil {
		return HarnessMaterialization{}, err
	}
	_ = json.Unmarshal(fileManifestRaw, &item.FileManifest)
	_ = json.Unmarshal(evidenceRaw, &item.EvidenceRefs)
	_ = json.Unmarshal(limitationsRaw, &item.Limitations)
	return item, nil
}

func ListHarnessMaterializations(ctx context.Context, db *sql.DB, profileRef string, limit int) ([]HarnessMaterialization, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT materialization_ref FROM defense_harness_materializations
		WHERE ($1='' OR profile_ref=$1) ORDER BY created_at DESC LIMIT $2`, strings.TrimSpace(profileRef), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := []string{}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]HarnessMaterialization, 0, len(refs))
	for _, ref := range refs {
		item, err := LoadHarnessMaterialization(ctx, db, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
