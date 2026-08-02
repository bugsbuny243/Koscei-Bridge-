package defense

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	UpgradeableLoaderID = "BPFLoaderUpgradeab1e11111111111111111111111"
	LegacyLoaderV2ID    = "BPFLoader2111111111111111111111111111111111"
	LegacyLoaderV1ID    = "BPFLoader1111111111111111111111111111111111"

	maxResolvedProgramBytes = 12 * 1024 * 1024
)

// DeploymentRPC is the read-only subset required by the on-chain deployment resolver.
type DeploymentRPC interface {
	Call(ctx context.Context, network, method string, params any, target any, ttl time.Duration) error
}

type DeploymentResolveInput struct {
	ProgramID           string `json:"program_id"`
	Network             string `json:"network"`
	ManifestArtifactRef string `json:"manifest_artifact_ref,omitempty"`
}

type DeploymentSnapshot struct {
	SnapshotRef          string    `json:"snapshot_ref"`
	ProgramID            string    `json:"program_id"`
	Network              string    `json:"network"`
	LoaderID             string    `json:"loader_id"`
	LoaderKind           string    `json:"loader_kind"`
	ProgramDataAddress   string    `json:"programdata_address,omitempty"`
	AccountSlot          uint64    `json:"account_slot"`
	DeploymentSlot       uint64    `json:"deployment_slot,omitempty"`
	UpgradeAuthority     string    `json:"upgrade_authority,omitempty"`
	UpgradeAuthorityOpen bool      `json:"upgrade_authority_open"`
	Executable           bool      `json:"executable"`
	FullBinaryHash       string    `json:"full_binary_hash"`
	CanonicalBinaryHash  string    `json:"canonical_binary_hash"`
	FullBinarySize       int       `json:"full_binary_size"`
	CanonicalBinarySize  int       `json:"canonical_binary_size"`
	TrailingZeroBytes    int       `json:"trailing_zero_bytes"`
	BinaryArtifactRef    string    `json:"binary_artifact_ref,omitempty"`
	ManifestArtifactRef  string    `json:"manifest_artifact_ref,omitempty"`
	SourceCommit         string    `json:"source_commit,omitempty"`
	MatchStatus          string    `json:"match_status"`
	MatchEvidenceStatus  string    `json:"match_evidence_status"`
	EvidenceRefs         []string  `json:"evidence_refs"`
	Limitations          []string  `json:"limitations"`
	SnapshotHash         string    `json:"snapshot_hash"`
	VerdictAuthority     bool      `json:"verdict_authority"`
	CreatedAt            time.Time `json:"created_at"`
}

type resolvedDeployment struct {
	DeploymentSnapshot
	FullBinary      []byte
	CanonicalBinary []byte
}

type rpcAccountInfo struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Value *struct {
		Data       []string `json:"data"`
		Executable bool     `json:"executable"`
		Owner      string   `json:"owner"`
		Space      uint64   `json:"space"`
	} `json:"value"`
}

// ResolveAndPersistDeployment reads a deployed Solana program without sending a transaction,
// stores its executable bytes as an immutable artifact and records a non-authoritative snapshot.
func ResolveAndPersistDeployment(ctx context.Context, db *sql.DB, rpc DeploymentRPC, input DeploymentResolveInput) (DeploymentSnapshot, error) {
	if db == nil {
		return DeploymentSnapshot{}, errors.New("database unavailable")
	}
	resolved, err := InspectProgramDeployment(ctx, rpc, input)
	if err != nil {
		return DeploymentSnapshot{}, err
	}
	artifact, err := storeResolvedBinaryArtifact(ctx, db, resolved)
	if err != nil {
		return DeploymentSnapshot{}, err
	}
	resolved.BinaryArtifactRef = artifact.ArtifactRef
	resolved.EvidenceRefs = append(resolved.EvidenceRefs, "artifact:"+artifact.ArtifactRef)

	match := matchDeploymentManifest(ctx, db, input.ManifestArtifactRef, resolved)
	resolved.ManifestArtifactRef = match.ManifestArtifactRef
	resolved.SourceCommit = match.SourceCommit
	resolved.MatchStatus = match.Status
	resolved.MatchEvidenceStatus = match.EvidenceStatus
	resolved.EvidenceRefs = append(resolved.EvidenceRefs, match.EvidenceRefs...)
	resolved.Limitations = append(resolved.Limitations, match.Limitations...)
	resolved.EvidenceRefs = uniqueStrings(resolved.EvidenceRefs)
	resolved.Limitations = uniqueStrings(resolved.Limitations)
	resolved.CreatedAt = time.Now().UTC()
	resolved.VerdictAuthority = false

	payload := map[string]any{
		"program_id":            resolved.ProgramID,
		"network":               resolved.Network,
		"loader_id":             resolved.LoaderID,
		"programdata_address":   resolved.ProgramDataAddress,
		"account_slot":          resolved.AccountSlot,
		"deployment_slot":       resolved.DeploymentSlot,
		"upgrade_authority":     resolved.UpgradeAuthority,
		"full_binary_hash":      resolved.FullBinaryHash,
		"canonical_binary_hash": resolved.CanonicalBinaryHash,
		"binary_artifact_ref":   resolved.BinaryArtifactRef,
		"manifest_artifact_ref": resolved.ManifestArtifactRef,
		"match_status":          resolved.MatchStatus,
	}
	resolved.SnapshotHash = hashJSON(payload)
	resolved.SnapshotRef = prefixedID("KDS1-", payload)

	evidenceRaw, _ := json.Marshal(resolved.EvidenceRefs)
	limitationsRaw, _ := json.Marshal(resolved.Limitations)
	_, err = db.ExecContext(ctx, `INSERT INTO defense_program_deployments
		(snapshot_ref,program_id,network,loader_id,loader_kind,programdata_address,account_slot,deployment_slot,upgrade_authority,
		 upgrade_authority_open,executable,full_binary_hash,canonical_binary_hash,full_binary_size,canonical_binary_size,trailing_zero_bytes,
		 binary_artifact_ref,manifest_artifact_ref,source_commit,match_status,match_evidence_status,evidence_refs,limitations,snapshot_hash,verdict_authority,created_at)
		VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,NULLIF($8,0),NULLIF($9,''),$10,$11,$12,$13,$14,$15,$16,$17,NULLIF($18,''),NULLIF($19,''),$20,$21,$22::jsonb,$23::jsonb,$24,false,$25)
		ON CONFLICT(snapshot_ref) DO NOTHING`,
		resolved.SnapshotRef, resolved.ProgramID, resolved.Network, resolved.LoaderID, resolved.LoaderKind, resolved.ProgramDataAddress,
		resolved.AccountSlot, resolved.DeploymentSlot, resolved.UpgradeAuthority, resolved.UpgradeAuthorityOpen, resolved.Executable,
		resolved.FullBinaryHash, resolved.CanonicalBinaryHash, resolved.FullBinarySize, resolved.CanonicalBinarySize, resolved.TrailingZeroBytes,
		resolved.BinaryArtifactRef, resolved.ManifestArtifactRef, resolved.SourceCommit, resolved.MatchStatus, resolved.MatchEvidenceStatus,
		string(evidenceRaw), string(limitationsRaw), resolved.SnapshotHash, resolved.CreatedAt)
	if err != nil {
		return DeploymentSnapshot{}, err
	}
	return resolved.DeploymentSnapshot, nil
}

// InspectProgramDeployment performs only read-only RPC inspection and pure parsing.
func InspectProgramDeployment(ctx context.Context, rpc DeploymentRPC, input DeploymentResolveInput) (resolvedDeployment, error) {
	if rpc == nil {
		return resolvedDeployment{}, errors.New("solana rpc unavailable")
	}
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.Network = normalizedNetwork(input.Network)
	if input.ProgramID == "" {
		return resolvedDeployment{}, errors.New("program_id is required")
	}
	programAccount, err := getDeploymentAccount(ctx, rpc, input.Network, input.ProgramID)
	if err != nil {
		return resolvedDeployment{}, fmt.Errorf("program account lookup failed: %w", err)
	}
	if programAccount.Value == nil {
		return resolvedDeployment{}, errors.New("program account not found")
	}
	programData, err := decodeRPCAccountData(programAccount)
	if err != nil {
		return resolvedDeployment{}, fmt.Errorf("program account decode failed: %w", err)
	}
	out := resolvedDeployment{DeploymentSnapshot: DeploymentSnapshot{
		ProgramID: input.ProgramID, Network: input.Network, LoaderID: programAccount.Value.Owner,
		AccountSlot: programAccount.Context.Slot, Executable: programAccount.Value.Executable,
		MatchStatus: "not_requested", MatchEvidenceStatus: "not_evaluated", VerdictAuthority: false,
		EvidenceRefs: []string{"rpc:getAccountInfo:" + input.ProgramID},
		Limitations:  []string{"Source identity is not established unless an independently produced build manifest matches the deployed bytecode hash."},
	}}

	switch programAccount.Value.Owner {
	case UpgradeableLoaderID:
		out.LoaderKind = "bpf_upgradeable_loader"
		programDataAddress, err := parseUpgradeableProgramAccount(programData)
		if err != nil {
			return resolvedDeployment{}, err
		}
		out.ProgramDataAddress = programDataAddress
		programDataAccount, err := getDeploymentAccount(ctx, rpc, input.Network, programDataAddress)
		if err != nil {
			return resolvedDeployment{}, fmt.Errorf("programdata lookup failed: %w", err)
		}
		if programDataAccount.Value == nil || programDataAccount.Value.Owner != UpgradeableLoaderID {
			return resolvedDeployment{}, errors.New("programdata account owner mismatch")
		}
		programDataBytes, err := decodeRPCAccountData(programDataAccount)
		if err != nil {
			return resolvedDeployment{}, fmt.Errorf("programdata decode failed: %w", err)
		}
		deploymentSlot, authority, binaryBytes, err := parseUpgradeableProgramData(programDataBytes)
		if err != nil {
			return resolvedDeployment{}, err
		}
		out.DeploymentSlot = deploymentSlot
		out.UpgradeAuthority = authority
		out.UpgradeAuthorityOpen = authority != ""
		out.FullBinary = binaryBytes
		out.EvidenceRefs = append(out.EvidenceRefs, "rpc:getAccountInfo:"+programDataAddress)
		if authority != "" {
			out.Limitations = append(out.Limitations, "Program remains upgradeable by the observed upgrade authority; deployed source equivalence can change after a later upgrade.")
		}
	case LegacyLoaderV2ID:
		out.LoaderKind = "bpf_loader_v2"
		out.FullBinary = programData
	case LegacyLoaderV1ID:
		out.LoaderKind = "bpf_loader_v1"
		out.FullBinary = programData
	default:
		return resolvedDeployment{}, fmt.Errorf("unsupported program loader: %s", programAccount.Value.Owner)
	}

	if len(out.FullBinary) == 0 || len(out.FullBinary) > maxResolvedProgramBytes {
		return resolvedDeployment{}, fmt.Errorf("resolved program bytecode size %d is outside the supported range", len(out.FullBinary))
	}
	out.CanonicalBinary, out.TrailingZeroBytes = trimTrailingZeroPadding(out.FullBinary)
	out.FullBinarySize = len(out.FullBinary)
	out.CanonicalBinarySize = len(out.CanonicalBinary)
	out.FullBinaryHash = hashValue(out.FullBinary)
	out.CanonicalBinaryHash = hashValue(out.CanonicalBinary)
	return out, nil
}

func getDeploymentAccount(ctx context.Context, rpc DeploymentRPC, network, address string) (rpcAccountInfo, error) {
	var result rpcAccountInfo
	err := rpc.Call(ctx, network, "getAccountInfo", []any{address, map[string]any{"encoding": "base64", "commitment": "confirmed"}}, &result, 30*time.Second)
	return result, err
}

func decodeRPCAccountData(account rpcAccountInfo) ([]byte, error) {
	if account.Value == nil || len(account.Value.Data) < 2 || account.Value.Data[1] != "base64" {
		return nil, errors.New("account data is not base64 encoded")
	}
	decoded, err := base64.StdEncoding.DecodeString(account.Value.Data[0])
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func parseUpgradeableProgramAccount(data []byte) (string, error) {
	if len(data) < 36 || binary.LittleEndian.Uint32(data[:4]) != 2 {
		return "", errors.New("invalid upgradeable Program account state")
	}
	return base58Encode(data[4:36]), nil
}

func parseUpgradeableProgramData(data []byte) (uint64, string, []byte, error) {
	if len(data) < 45 || binary.LittleEndian.Uint32(data[:4]) != 3 {
		return 0, "", nil, errors.New("invalid upgradeable ProgramData account state")
	}
	slot := binary.LittleEndian.Uint64(data[4:12])
	var authority string
	switch data[12] {
	case 0:
	case 1:
		authority = base58Encode(data[13:45])
	default:
		return 0, "", nil, errors.New("invalid upgrade authority option tag")
	}
	binaryBytes := append([]byte(nil), data[45:]...)
	if len(binaryBytes) == 0 {
		return 0, "", nil, errors.New("programdata contains no executable bytes")
	}
	return slot, authority, binaryBytes, nil
}

func trimTrailingZeroPadding(data []byte) ([]byte, int) {
	end := len(data)
	for end > 1 && data[end-1] == 0 {
		end--
	}
	return append([]byte(nil), data[:end]...), len(data) - end
}

func storeResolvedBinaryArtifact(ctx context.Context, db *sql.DB, deployment resolvedDeployment) (Artifact, error) {
	metadata := map[string]any{
		"source":                  "solana_rpc",
		"loader_id":               deployment.LoaderID,
		"loader_kind":             deployment.LoaderKind,
		"programdata_address":     deployment.ProgramDataAddress,
		"account_slot":            deployment.AccountSlot,
		"deployment_slot":         deployment.DeploymentSlot,
		"upgrade_authority":       deployment.UpgradeAuthority,
		"full_binary_sha256":      deployment.FullBinaryHash,
		"canonical_binary_sha256": deployment.CanonicalBinaryHash,
		"full_binary_size":        deployment.FullBinarySize,
		"canonical_binary_size":   deployment.CanonicalBinarySize,
		"trailing_zero_bytes":     deployment.TrailingZeroBytes,
	}
	metadataRaw, _ := json.Marshal(metadata)
	ref := prefixedID("KDA1-", map[string]any{"program": deployment.ProgramID, "network": deployment.Network, "type": "sbpf_bytecode", "hash": deployment.FullBinaryHash})
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx, `INSERT INTO defense_program_artifacts
		(artifact_ref,program_id,network,artifact_type,source_uri,source_commit,framework,framework_version,runtime_version,content_hash,content_encoding,content_bytes,metadata,trust_level,verified,created_by,created_at)
		VALUES($1,$2,$3,'sbpf_bytecode','solana-rpc://getAccountInfo',NULL,NULL,NULL,NULL,$4,'base64',$5,$6::jsonb,'observed',false,'system',$7)
		ON CONFLICT(artifact_ref) DO NOTHING`, ref, deployment.ProgramID, deployment.Network, deployment.FullBinaryHash, deployment.FullBinary, string(metadataRaw), now)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{ArtifactRef: ref, ProgramID: deployment.ProgramID, Network: deployment.Network, ArtifactType: "sbpf_bytecode",
		SourceURI: "solana-rpc://getAccountInfo", ContentHash: deployment.FullBinaryHash, ContentEncoding: "base64", Content: deployment.FullBinary,
		Metadata: metadata, TrustLevel: "observed", Verified: false, CreatedBy: "system", CreatedAt: now}, nil
}

type deploymentManifestMatch struct {
	ManifestArtifactRef string
	SourceCommit        string
	Status              string
	EvidenceStatus      string
	EvidenceRefs        []string
	Limitations         []string
}

func matchDeploymentManifest(ctx context.Context, db *sql.DB, ref string, deployment resolvedDeployment) deploymentManifestMatch {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return deploymentManifestMatch{Status: "not_requested", EvidenceStatus: "not_evaluated",
			Limitations: []string{"No build manifest was supplied, so deployed bytecode was not matched to a source commit."}}
	}
	result := deploymentManifestMatch{ManifestArtifactRef: ref, Status: "invalid_manifest", EvidenceStatus: "insufficient",
		EvidenceRefs: []string{"artifact:" + ref}}
	artifact, err := LoadArtifact(ctx, db, ref)
	if err != nil {
		result.Limitations = []string{"Build manifest artifact could not be loaded."}
		return result
	}
	if artifact.ArtifactType != "source_manifest" && artifact.ArtifactType != "sbpf_manifest" {
		result.Limitations = []string{"Supplied artifact is not a source_manifest or sbpf_manifest."}
		return result
	}
	if artifact.ProgramID != deployment.ProgramID || normalizedNetwork(artifact.Network) != deployment.Network {
		result.Limitations = []string{"Build manifest program or network does not match the deployed target."}
		return result
	}
	var manifest struct {
		SchemaVersion         string `json:"schema_version"`
		ProgramID             string `json:"program_id"`
		Network               string `json:"network"`
		SourceCommit          string `json:"source_commit"`
		CompiledBinarySHA256  string `json:"compiled_binary_sha256"`
		BinarySHA256          string `json:"binary_sha256"`
		FullBinarySHA256      string `json:"full_binary_sha256"`
		CanonicalBinarySHA256 string `json:"canonical_binary_sha256"`
	}
	if err := json.Unmarshal(artifact.Content, &manifest); err != nil {
		result.Limitations = []string{"Build manifest content is not valid JSON."}
		return result
	}
	result.SourceCommit = strings.TrimSpace(manifest.SourceCommit)
	if result.SourceCommit == "" {
		result.SourceCommit = artifact.SourceCommit
	}
	candidates := uniqueStrings([]string{manifest.CompiledBinarySHA256, manifest.BinarySHA256, manifest.FullBinarySHA256, manifest.CanonicalBinarySHA256})
	for _, candidate := range candidates {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		switch candidate {
		case strings.ToLower(deployment.FullBinaryHash):
			result.Status = "matched_full_binary"
			result.EvidenceStatus = "observed"
			return result
		case strings.ToLower(deployment.CanonicalBinaryHash):
			result.Status = "matched_after_zero_padding_normalization"
			result.EvidenceStatus = "observed"
			result.Limitations = []string{"Match required removal of trailing zero allocation padding; the canonical hash matched but the full account-data hash did not necessarily match."}
			return result
		}
	}
	if len(candidates) == 0 {
		result.Limitations = []string{"Build manifest contains no supported binary SHA-256 field."}
		return result
	}
	result.Status = "mismatched"
	result.EvidenceStatus = "contradicted"
	result.Limitations = []string{"Declared build hash does not match the deployed full or canonical bytecode hash."}
	return result
}

func ListDeploymentSnapshots(ctx context.Context, db *sql.DB, programID, network string, limit int) ([]DeploymentSnapshot, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	programID = strings.TrimSpace(programID)
	network = normalizedNetwork(network)
	rows, err := db.QueryContext(ctx, `SELECT snapshot_ref,program_id,network,loader_id,loader_kind,COALESCE(programdata_address,''),account_slot,
		COALESCE(deployment_slot,0),COALESCE(upgrade_authority,''),upgrade_authority_open,executable,full_binary_hash,canonical_binary_hash,
		full_binary_size,canonical_binary_size,trailing_zero_bytes,binary_artifact_ref,COALESCE(manifest_artifact_ref,''),COALESCE(source_commit,''),
		match_status,match_evidence_status,evidence_refs,limitations,snapshot_hash,verdict_authority,created_at
		FROM defense_program_deployments WHERE ($1='' OR program_id=$1) AND network=$2 ORDER BY created_at DESC LIMIT $3`, programID, network, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeploymentSnapshot{}
	for rows.Next() {
		var item DeploymentSnapshot
		var evidenceRaw, limitationsRaw []byte
		if err := rows.Scan(&item.SnapshotRef, &item.ProgramID, &item.Network, &item.LoaderID, &item.LoaderKind, &item.ProgramDataAddress,
			&item.AccountSlot, &item.DeploymentSlot, &item.UpgradeAuthority, &item.UpgradeAuthorityOpen, &item.Executable,
			&item.FullBinaryHash, &item.CanonicalBinaryHash, &item.FullBinarySize, &item.CanonicalBinarySize, &item.TrailingZeroBytes,
			&item.BinaryArtifactRef, &item.ManifestArtifactRef, &item.SourceCommit, &item.MatchStatus, &item.MatchEvidenceStatus,
			&evidenceRaw, &limitationsRaw, &item.SnapshotHash, &item.VerdictAuthority, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidenceRaw, &item.EvidenceRefs)
		_ = json.Unmarshal(limitationsRaw, &item.Limitations)
		out = append(out, item)
	}
	return out, rows.Err()
}

func hashJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return hashValue(encoded)
}

func base58Encode(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	if len(input) == 0 {
		return ""
	}
	digits := []byte{}
	for _, value := range input {
		carry := int(value)
		for i := 0; i < len(digits); i++ {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	for _, value := range input {
		if value != 0 {
			break
		}
		digits = append(digits, 0)
	}
	var builder strings.Builder
	for i := len(digits) - 1; i >= 0; i-- {
		builder.WriteByte(alphabet[digits[i]])
	}
	return builder.String()
}
