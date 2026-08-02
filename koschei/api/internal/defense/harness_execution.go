package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const HarnessExecutionProfileVersion = "v1.0.0"

const (
	HarnessEngineLiteSVM = "litesvm"
	HarnessEngineTrident = "trident"
)

type ConfirmedHarnessInvariant struct {
	TemplateID string `json:"template_id"`
	Statement  string `json:"statement"`
}

type HarnessToolPin struct {
	AttestationRef    string    `json:"attestation_ref"`
	ToolName          string    `json:"tool_name"`
	VersionOutput     string    `json:"version_output"`
	VersionHash       string    `json:"version_hash"`
	BinaryPath        string    `json:"binary_path"`
	BinaryHash        string    `json:"binary_hash"`
	WorkerImageDigest string    `json:"worker_image_digest"`
	ObservedAt        time.Time `json:"observed_at"`
}

type HarnessExecutionProfileInput struct {
	PlanRef             string                      `json:"plan_ref"`
	HarnessArtifactRef  string                      `json:"harness_artifact_ref"`
	Engine              string                      `json:"engine"`
	WorkerID            string                      `json:"worker_id"`
	WorkerImageDigest   string                      `json:"worker_image_digest"`
	ConfirmedInvariants []ConfirmedHarnessInvariant `json:"confirmed_invariants"`
	MaxDurationSeconds  int                         `json:"max_duration_seconds"`
	MaxOutputBytes      int                         `json:"max_output_bytes"`
}

type HarnessExecutionProfile struct {
	ProfileRef          string                      `json:"profile_ref"`
	ProfileVersion      string                      `json:"profile_version"`
	PlanRef             string                      `json:"plan_ref"`
	HarnessArtifactRef  string                      `json:"harness_artifact_ref"`
	ProgramID           string                      `json:"program_id"`
	Network             string                      `json:"network"`
	Engine              string                      `json:"engine"`
	WorkerID            string                      `json:"worker_id"`
	WorkerImageDigest   string                      `json:"worker_image_digest"`
	RequiredTools       []string                    `json:"required_tools"`
	ToolPins            []HarnessToolPin            `json:"tool_pins"`
	ConfirmedInvariants []ConfirmedHarnessInvariant `json:"confirmed_invariants"`
	CommandPolicy       map[string]any              `json:"command_policy"`
	MaxDurationSeconds  int                         `json:"max_duration_seconds"`
	MaxOutputBytes      int                         `json:"max_output_bytes"`
	ReadinessStatus     string                      `json:"readiness_status"`
	ExecutionAllowed    bool                        `json:"execution_allowed"`
	EvidenceRefs        []string                    `json:"evidence_refs"`
	Limitations         []string                    `json:"limitations"`
	ProfileHash         string                      `json:"profile_hash"`
	VerdictAuthority    bool                        `json:"verdict_authority"`
	CreatedAt           time.Time                   `json:"created_at"`
}

type harnessPlanExecutionSource struct {
	PlanRef            string
	PlanVersion        string
	ProgramID          string
	Network            string
	IDLArtifactRef     string
	SourceArtifactRef  string
	PlanHash           string
	InvariantTemplates []HarnessInvariantTemplate
}

// CreateHarnessExecutionProfile evaluates and persists an immutable execution
// gate. It does not execute source or enqueue a worker job. Missing pinning
// evidence is persisted as a blocked profile rather than being interpreted as
// permission.
func CreateHarnessExecutionProfile(ctx context.Context, db *sql.DB, input HarnessExecutionProfileInput) (HarnessExecutionProfile, error) {
	if db == nil {
		return HarnessExecutionProfile{}, errors.New("database unavailable")
	}
	input.PlanRef = strings.TrimSpace(input.PlanRef)
	input.HarnessArtifactRef = strings.TrimSpace(input.HarnessArtifactRef)
	input.Engine = strings.ToLower(strings.TrimSpace(input.Engine))
	input.WorkerID = strings.TrimSpace(input.WorkerID)
	input.WorkerImageDigest = normalizeDefenseSHA256Digest(input.WorkerImageDigest)
	if input.PlanRef == "" || input.HarnessArtifactRef == "" || input.WorkerID == "" {
		return HarnessExecutionProfile{}, errors.New("plan_ref, harness_artifact_ref and worker_id are required")
	}
	if input.WorkerImageDigest == "" {
		return HarnessExecutionProfile{}, errors.New("worker_image_digest must be a sha256 digest")
	}
	requiredTools, err := requiredHarnessTools(input.Engine)
	if err != nil {
		return HarnessExecutionProfile{}, err
	}
	if input.MaxDurationSeconds == 0 {
		input.MaxDurationSeconds = 120
	}
	if input.MaxDurationSeconds < 30 || input.MaxDurationSeconds > 900 {
		return HarnessExecutionProfile{}, errors.New("max_duration_seconds must be between 30 and 900")
	}
	if input.MaxOutputBytes == 0 {
		input.MaxOutputBytes = 256 * 1024
	}
	if input.MaxOutputBytes < 16*1024 || input.MaxOutputBytes > 1024*1024 {
		return HarnessExecutionProfile{}, errors.New("max_output_bytes must be between 16384 and 1048576")
	}

	plan, err := loadHarnessPlanExecutionSource(ctx, db, input.PlanRef)
	if err != nil {
		return HarnessExecutionProfile{}, err
	}
	confirmed, err := validateConfirmedHarnessInvariants(plan.InvariantTemplates, input.ConfirmedInvariants)
	if err != nil {
		return HarnessExecutionProfile{}, err
	}
	harnessArtifact, err := LoadArtifact(ctx, db, input.HarnessArtifactRef)
	if err != nil {
		return HarnessExecutionProfile{}, errors.New("harness artifact not found")
	}
	if harnessArtifact.ArtifactType != "source_bundle" || harnessArtifact.ProgramID != plan.ProgramID || harnessArtifact.Network != plan.Network {
		return HarnessExecutionProfile{}, errors.New("harness artifact must be a matching source_bundle")
	}
	if strings.ToLower(strings.TrimSpace(harnessArtifactMetadataString(harnessArtifact.Metadata, "artifact_role"))) != "harness" {
		return HarnessExecutionProfile{}, errors.New("harness artifact metadata must declare artifact_role=harness")
	}
	if strings.TrimSpace(harnessArtifactMetadataString(harnessArtifact.Metadata, "harness_plan_ref")) != plan.PlanRef {
		return HarnessExecutionProfile{}, errors.New("harness artifact is not bound to the requested plan")
	}

	limitations := []string{}
	if plan.SourceArtifactRef == "" {
		limitations = append(limitations, "Phase 11 plan is not bound to a target source artifact.")
	}
	toolPins := []HarnessToolPin{}
	for _, toolName := range requiredTools {
		attestation, loadErr := loadLatestPinnedToolAttestation(ctx, db, input.WorkerID, toolName)
		if errors.Is(loadErr, sql.ErrNoRows) {
			limitations = append(limitations, fmt.Sprintf("No toolchain attestation exists for required tool %s on worker %s.", toolName, input.WorkerID))
			continue
		}
		if loadErr != nil {
			return HarnessExecutionProfile{}, loadErr
		}
		toolPins = append(toolPins, HarnessToolPin{
			AttestationRef:    attestation.AttestationRef,
			ToolName:          attestation.ToolName,
			VersionOutput:     attestation.VersionOutput,
			VersionHash:       attestation.VersionHash,
			BinaryPath:        attestation.BinaryPath,
			BinaryHash:        attestation.BinaryHash,
			WorkerImageDigest: attestation.WorkerImageDigest,
			ObservedAt:        attestation.ObservedAt,
		})
		if !attestation.Available {
			limitations = append(limitations, fmt.Sprintf("Required tool %s is unavailable on the selected worker.", toolName))
		}
		if !attestation.Pinned {
			limitations = append(limitations, fmt.Sprintf("Required tool %s lacks an executable hash or immutable worker image pin.", toolName))
		}
		if attestation.WorkerImageDigest != input.WorkerImageDigest {
			limitations = append(limitations, fmt.Sprintf("Required tool %s was attested on a different worker image digest.", toolName))
		}
		if normalizeDefenseSHA256Digest(attestation.VersionHash) == "" {
			limitations = append(limitations, fmt.Sprintf("Required tool %s lacks a valid version-output hash.", toolName))
		}
	}
	sort.Slice(toolPins, func(i, j int) bool { return toolPins[i].ToolName < toolPins[j].ToolName })
	limitations = uniqueStrings(limitations)
	commandPolicy := harnessCommandPolicy(input.Engine)
	status := "blocked"
	executionAllowed := false
	if len(limitations) == 0 {
		status = "ready"
		executionAllowed = true
	}

	evidenceRefs := []string{
		"harness_plan:" + plan.PlanRef,
		"artifact:" + plan.IDLArtifactRef,
		"artifact:" + harnessArtifact.ArtifactRef,
	}
	if plan.SourceArtifactRef != "" {
		evidenceRefs = append(evidenceRefs, "artifact:"+plan.SourceArtifactRef)
	}
	for _, pin := range toolPins {
		evidenceRefs = append(evidenceRefs, "toolchain_attestation:"+pin.AttestationRef)
	}
	evidenceRefs = uniqueStrings(evidenceRefs)
	payload := map[string]any{
		"schema_version":        "koschei-harness-execution-profile-v1",
		"profile_version":       HarnessExecutionProfileVersion,
		"plan_ref":              plan.PlanRef,
		"plan_hash":             plan.PlanHash,
		"harness_artifact_ref":  harnessArtifact.ArtifactRef,
		"harness_artifact_hash": harnessArtifact.ContentHash,
		"program_id":            plan.ProgramID,
		"network":               plan.Network,
		"engine":                input.Engine,
		"worker_id":             input.WorkerID,
		"worker_image_digest":   input.WorkerImageDigest,
		"required_tools":        requiredTools,
		"tool_pins":             toolPins,
		"confirmed_invariants":  confirmed,
		"command_policy":        commandPolicy,
		"max_duration_seconds":  input.MaxDurationSeconds,
		"max_output_bytes":      input.MaxOutputBytes,
		"readiness_status":      status,
		"execution_allowed":     executionAllowed,
		"evidence_refs":         evidenceRefs,
		"limitations":           limitations,
	}
	profileHash := hashJSON(payload)
	profileRef := prefixedID("KHEP1-", payload)
	requiredToolsRaw, _ := json.Marshal(requiredTools)
	toolPinsRaw, _ := json.Marshal(toolPins)
	confirmedRaw, _ := json.Marshal(confirmed)
	commandPolicyRaw, _ := json.Marshal(commandPolicy)
	evidenceRaw, _ := json.Marshal(evidenceRefs)
	limitationsRaw, _ := json.Marshal(limitations)
	now := time.Now().UTC()
	_, err = db.ExecContext(ctx, `INSERT INTO defense_harness_execution_profiles
		(profile_ref,profile_version,plan_ref,harness_artifact_ref,program_id,network,engine,worker_id,worker_image_digest,
		 required_tools,tool_pins,confirmed_invariants,command_policy,max_duration_seconds,max_output_bytes,readiness_status,
		 execution_allowed,evidence_refs,limitations,profile_hash,verdict_authority,created_by,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13::jsonb,$14,$15,$16,$17,
		 $18::jsonb,$19::jsonb,$20,false,'owner',$21)
		ON CONFLICT(profile_ref) DO NOTHING`,
		profileRef, HarnessExecutionProfileVersion, plan.PlanRef, harnessArtifact.ArtifactRef, plan.ProgramID, plan.Network,
		input.Engine, input.WorkerID, input.WorkerImageDigest, string(requiredToolsRaw), string(toolPinsRaw), string(confirmedRaw),
		string(commandPolicyRaw), input.MaxDurationSeconds, input.MaxOutputBytes, status, executionAllowed, string(evidenceRaw),
		string(limitationsRaw), profileHash, now)
	if err != nil {
		return HarnessExecutionProfile{}, err
	}
	return LoadHarnessExecutionProfile(ctx, db, profileRef)
}

func LoadHarnessExecutionProfile(ctx context.Context, db *sql.DB, profileRef string) (HarnessExecutionProfile, error) {
	if db == nil {
		return HarnessExecutionProfile{}, errors.New("database unavailable")
	}
	var profile HarnessExecutionProfile
	var requiredToolsRaw, toolPinsRaw, confirmedRaw, commandPolicyRaw, evidenceRaw, limitationsRaw []byte
	err := db.QueryRowContext(ctx, `SELECT profile_ref,profile_version,plan_ref,harness_artifact_ref,program_id,network,engine,
		worker_id,worker_image_digest,required_tools,tool_pins,confirmed_invariants,command_policy,max_duration_seconds,
		max_output_bytes,readiness_status,execution_allowed,evidence_refs,limitations,profile_hash,verdict_authority,created_at
		FROM defense_harness_execution_profiles WHERE profile_ref=$1`, strings.TrimSpace(profileRef)).Scan(
		&profile.ProfileRef, &profile.ProfileVersion, &profile.PlanRef, &profile.HarnessArtifactRef, &profile.ProgramID,
		&profile.Network, &profile.Engine, &profile.WorkerID, &profile.WorkerImageDigest, &requiredToolsRaw, &toolPinsRaw,
		&confirmedRaw, &commandPolicyRaw, &profile.MaxDurationSeconds, &profile.MaxOutputBytes, &profile.ReadinessStatus,
		&profile.ExecutionAllowed, &evidenceRaw, &limitationsRaw, &profile.ProfileHash, &profile.VerdictAuthority, &profile.CreatedAt)
	if err != nil {
		return HarnessExecutionProfile{}, err
	}
	_ = json.Unmarshal(requiredToolsRaw, &profile.RequiredTools)
	_ = json.Unmarshal(toolPinsRaw, &profile.ToolPins)
	_ = json.Unmarshal(confirmedRaw, &profile.ConfirmedInvariants)
	_ = json.Unmarshal(commandPolicyRaw, &profile.CommandPolicy)
	_ = json.Unmarshal(evidenceRaw, &profile.EvidenceRefs)
	_ = json.Unmarshal(limitationsRaw, &profile.Limitations)
	return profile, nil
}

func ListHarnessExecutionProfiles(ctx context.Context, db *sql.DB, planRef, workerID string, limit int) ([]HarnessExecutionProfile, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT profile_ref FROM defense_harness_execution_profiles
		WHERE ($1='' OR plan_ref=$1) AND ($2='' OR worker_id=$2)
		ORDER BY created_at DESC LIMIT $3`, strings.TrimSpace(planRef), strings.TrimSpace(workerID), limit)
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
	out := make([]HarnessExecutionProfile, 0, len(refs))
	for _, ref := range refs {
		profile, err := LoadHarnessExecutionProfile(ctx, db, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, profile)
	}
	return out, nil
}

// AuthorizeHarnessExecution is the mandatory future worker boundary. Phase 12A
// exposes no execution action, but later phases must call this function with the
// live worker identity before any command is launched. It re-resolves and hashes
// every required executable to close the gap between startup attestation and
// execution time.
func AuthorizeHarnessExecution(ctx context.Context, db *sql.DB, profileRef, workerID, workerImageDigest string) (HarnessExecutionProfile, error) {
	profile, err := LoadHarnessExecutionProfile(ctx, db, profileRef)
	if err != nil {
		return HarnessExecutionProfile{}, err
	}
	if profile.ReadinessStatus != "ready" || !profile.ExecutionAllowed {
		return HarnessExecutionProfile{}, errors.New("harness execution profile is blocked")
	}
	if strings.TrimSpace(workerID) == "" || strings.TrimSpace(workerID) != profile.WorkerID {
		return HarnessExecutionProfile{}, errors.New("worker identity does not match the execution profile")
	}
	workerImageDigest = normalizeDefenseSHA256Digest(workerImageDigest)
	if workerImageDigest == "" || workerImageDigest != profile.WorkerImageDigest {
		return HarnessExecutionProfile{}, errors.New("worker image digest does not match the execution profile")
	}
	if err := validateRuntimeHarnessToolPins(profile); err != nil {
		return HarnessExecutionProfile{}, err
	}
	return profile, nil
}

func validateRuntimeHarnessToolPins(profile HarnessExecutionProfile) error {
	if len(profile.RequiredTools) == 0 || len(profile.ToolPins) != len(profile.RequiredTools) {
		return errors.New("execution profile tool pin set is incomplete")
	}
	pins := make(map[string]HarnessToolPin, len(profile.ToolPins))
	for _, pin := range profile.ToolPins {
		name := strings.TrimSpace(pin.ToolName)
		if name == "" || pins[name].ToolName != "" {
			return errors.New("execution profile contains an invalid or duplicate tool pin")
		}
		if pin.WorkerImageDigest != profile.WorkerImageDigest {
			return fmt.Errorf("tool %s image digest does not match the execution profile", name)
		}
		if normalizeDefenseSHA256Digest(pin.BinaryHash) == "" || normalizeDefenseSHA256Digest(pin.VersionHash) == "" {
			return fmt.Errorf("tool %s lacks a valid executable or version hash", name)
		}
		pins[name] = pin
	}
	for _, required := range profile.RequiredTools {
		pin, ok := pins[required]
		if !ok {
			return fmt.Errorf("required tool %s is not pinned", required)
		}
		resolved, err := exec.LookPath(required)
		if err != nil || strings.TrimSpace(resolved) == "" {
			return fmt.Errorf("required tool %s cannot be resolved at execution time", required)
		}
		if filepath.Clean(resolved) != filepath.Clean(pin.BinaryPath) {
			return fmt.Errorf("required tool %s resolved path changed after attestation", required)
		}
		currentHash, err := hashDefenseExecutable(resolved)
		if err != nil {
			return fmt.Errorf("required tool %s cannot be hashed at execution time", required)
		}
		if currentHash != pin.BinaryHash {
			return fmt.Errorf("required tool %s executable hash changed after attestation", required)
		}
	}
	return nil
}

func loadHarnessPlanExecutionSource(ctx context.Context, db *sql.DB, planRef string) (harnessPlanExecutionSource, error) {
	var plan harnessPlanExecutionSource
	var planRaw []byte
	err := db.QueryRowContext(ctx, `SELECT plan_ref,plan_version,program_id,network,idl_artifact_ref,COALESCE(source_artifact_ref,''),plan_hash,plan_json
		FROM defense_harness_plans WHERE plan_ref=$1`, strings.TrimSpace(planRef)).Scan(
		&plan.PlanRef, &plan.PlanVersion, &plan.ProgramID, &plan.Network, &plan.IDLArtifactRef, &plan.SourceArtifactRef,
		&plan.PlanHash, &planRaw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return harnessPlanExecutionSource{}, errors.New("harness plan not found")
		}
		return harnessPlanExecutionSource{}, err
	}
	var payload struct {
		InvariantTemplates []HarnessInvariantTemplate `json:"invariant_templates"`
	}
	if err := json.Unmarshal(planRaw, &payload); err != nil {
		return harnessPlanExecutionSource{}, errors.New("stored harness plan is invalid")
	}
	plan.InvariantTemplates = payload.InvariantTemplates
	return plan, nil
}

func validateConfirmedHarnessInvariants(templates []HarnessInvariantTemplate, confirmed []ConfirmedHarnessInvariant) ([]ConfirmedHarnessInvariant, error) {
	if len(confirmed) == 0 || len(confirmed) > 50 {
		return nil, errors.New("one to fifty confirmed invariants are required")
	}
	valid := map[string]bool{}
	for _, template := range templates {
		valid[strings.TrimSpace(template.TemplateID)] = true
	}
	seen := map[string]bool{}
	out := make([]ConfirmedHarnessInvariant, 0, len(confirmed))
	for _, item := range confirmed {
		item.TemplateID = strings.TrimSpace(item.TemplateID)
		item.Statement = strings.TrimSpace(item.Statement)
		if !valid[item.TemplateID] {
			return nil, fmt.Errorf("confirmed invariant references unknown template: %s", item.TemplateID)
		}
		if seen[item.TemplateID] {
			return nil, fmt.Errorf("confirmed invariant template is duplicated: %s", item.TemplateID)
		}
		if item.Statement == "" || len(item.Statement) > 1200 {
			return nil, fmt.Errorf("confirmed invariant statement is invalid: %s", item.TemplateID)
		}
		seen[item.TemplateID] = true
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TemplateID < out[j].TemplateID })
	return out, nil
}

func requiredHarnessTools(engine string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case HarnessEngineLiteSVM:
		return []string{"cargo", "rustc"}, nil
	case HarnessEngineTrident:
		return []string{"anchor", "cargo", "rustc", "solana", "trident"}, nil
	default:
		return nil, errors.New("unsupported harness engine")
	}
}

func harnessCommandPolicy(engine string) map[string]any {
	command := "cargo test --locked --offline"
	if engine == HarnessEngineTrident {
		command = "trident fuzz run"
	}
	return map[string]any{
		"policy_version":           "koschei-harness-command-policy-v1",
		"engine":                   engine,
		"commands":                 []string{command},
		"arbitrary_commands":       false,
		"network_access":           false,
		"wallet_keys":              false,
		"mainnet_rpc":              false,
		"mainnet_transaction_sent": false,
	}
}

func loadLatestPinnedToolAttestation(ctx context.Context, db *sql.DB, workerID, toolName string) (PinnedToolchainAttestation, error) {
	var item PinnedToolchainAttestation
	var limitationsRaw []byte
	err := db.QueryRowContext(ctx, `SELECT attestation_ref,worker_id,COALESCE(worker_image_digest,''),tool_name,command,available,
		version_output,version_hash,COALESCE(binary_path,''),COALESCE(binary_hash,''),evidence_status,limitations,
		attestation_hash,verdict_authority,observed_at
		FROM defense_toolchain_attestations WHERE worker_id=$1 AND tool_name=$2
		ORDER BY observed_at DESC LIMIT 1`, strings.TrimSpace(workerID), strings.TrimSpace(toolName)).Scan(
		&item.AttestationRef, &item.WorkerID, &item.WorkerImageDigest, &item.ToolName, &item.Command, &item.Available,
		&item.VersionOutput, &item.VersionHash, &item.BinaryPath, &item.BinaryHash, &item.EvidenceStatus, &limitationsRaw,
		&item.AttestationHash, &item.VerdictAuthority, &item.ObservedAt)
	if err != nil {
		return PinnedToolchainAttestation{}, err
	}
	_ = json.Unmarshal(limitationsRaw, &item.Limitations)
	item.Pinned = item.Available && normalizeDefenseSHA256Digest(item.WorkerImageDigest) != "" && normalizeDefenseSHA256Digest(item.BinaryHash) != ""
	return item, nil
}

func harnessArtifactMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}
