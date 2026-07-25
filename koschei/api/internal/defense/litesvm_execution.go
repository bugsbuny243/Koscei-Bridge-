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
	"unicode/utf8"
)

const (
	WorkerActionRunLiteSVMHarness   = "run_litesvm_harness"
	LiteSVMExecutionAttemptVersion = "v1.0.0"
	liteSVMSandboxPolicyVersion     = "koschei-bwrap-litesvm-v1"
)

var fixedLiteSVMCommandArgv = []string{"cargo", "test", "--locked", "--offline"}

type LiteSVMExecutableEvidence struct {
	ToolName          string `json:"tool_name"`
	AttestationRef    string `json:"attestation_ref"`
	VersionHash       string `json:"version_hash"`
	BinaryPath        string `json:"binary_path"`
	BinaryHash        string `json:"binary_hash"`
	WorkerImageDigest string `json:"worker_image_digest"`
}

type LiteSVMExecutionPlan struct {
	JobRef                   string                      `json:"job_ref"`
	Profile                  HarnessExecutionProfile     `json:"profile"`
	Materialization          HarnessMaterialization      `json:"materialization"`
	SourceHarnessArtifact    Artifact                    `json:"-"`
	MaterializedArtifact     Artifact                    `json:"-"`
	Bundle                   map[string]string           `json:"-"`
	CommandArgv              []string                    `json:"command_argv"`
	CommandHash              string                      `json:"command_hash"`
	SandboxPolicy            map[string]any              `json:"sandbox_policy"`
	SandboxPolicyHash        string                      `json:"sandbox_policy_hash"`
	EnvironmentTemplate      map[string]string           `json:"environment_template"`
	EnvironmentHash          string                      `json:"environment_hash"`
	InputHash                string                      `json:"input_hash"`
	ToolAttestationRefs      []string                    `json:"tool_attestation_refs"`
	ExecutableEvidence       []LiteSVMExecutableEvidence `json:"executable_evidence"`
	CargoExecutablePath      string                      `json:"cargo_executable_path"`
	CargoExecutableHash      string                      `json:"cargo_executable_hash"`
	SandboxExecutablePath    string                      `json:"sandbox_executable_path"`
	SandboxExecutableHash    string                      `json:"sandbox_executable_hash"`
	MaxDurationSeconds       int                         `json:"max_duration_seconds"`
	MaxOutputBytes           int                         `json:"max_output_bytes"`
	NetworkAccess            bool                        `json:"network_access"`
	DependencyResolution     bool                        `json:"dependency_resolution"`
	WalletMaterialAccessed   bool                        `json:"wallet_material_accessed"`
	MainnetRPCAccessed       bool                        `json:"mainnet_rpc_accessed"`
	MainnetTransactionSent   bool                        `json:"mainnet_transaction_sent"`
	VerdictAuthority         bool                        `json:"verdict_authority"`
}

type LiteSVMExecutionOutcome struct {
	AttemptNumber     int       `json:"attempt_number"`
	Status            string    `json:"status"`
	StartedAt         time.Time `json:"started_at"`
	CompletedAt       time.Time `json:"completed_at"`
	ExitCode          *int      `json:"exit_code,omitempty"`
	TerminationReason string    `json:"termination_reason"`
	Stdout            string    `json:"stdout"`
	Stderr            string    `json:"stderr"`
	StdoutTruncated   bool      `json:"stdout_truncated"`
	StderrTruncated   bool      `json:"stderr_truncated"`
	SourceExecuted    bool      `json:"source_executed"`
	HarnessExecuted   bool      `json:"harness_executed"`
	Limitations       []string  `json:"limitations"`
}

type LiteSVMExecutionAttempt struct {
	AttemptRef                string                      `json:"attempt_ref"`
	AttemptVersion            string                      `json:"attempt_version"`
	JobRef                    string                      `json:"job_ref"`
	AttemptNumber             int                         `json:"attempt_number"`
	ProfileRef                string                      `json:"profile_ref"`
	ProfileHash               string                      `json:"profile_hash"`
	MaterializationRef        string                      `json:"materialization_ref"`
	MaterializationHash       string                      `json:"materialization_hash"`
	SourceHarnessArtifactRef  string                      `json:"source_harness_artifact_ref"`
	SourceHarnessArtifactHash string                      `json:"source_harness_artifact_hash"`
	MaterializedArtifactRef   string                      `json:"materialized_artifact_ref"`
	MaterializedArtifactHash  string                      `json:"materialized_artifact_hash"`
	ProgramID                 string                      `json:"program_id"`
	Network                   string                      `json:"network"`
	Engine                    string                      `json:"engine"`
	WorkerID                  string                      `json:"worker_id"`
	WorkerImageDigest         string                      `json:"worker_image_digest"`
	ToolAttestationRefs       []string                    `json:"tool_attestation_refs"`
	ExecutableEvidence        []LiteSVMExecutableEvidence `json:"executable_evidence"`
	CommandArgv               []string                    `json:"command_argv"`
	CommandHash               string                      `json:"command_hash"`
	SandboxPolicy             map[string]any              `json:"sandbox_policy"`
	SandboxPolicyHash         string                      `json:"sandbox_policy_hash"`
	EnvironmentHash           string                      `json:"environment_hash"`
	InputHash                 string                      `json:"input_hash"`
	CargoManifestHash         string                      `json:"cargo_manifest_hash"`
	CargoLockHash             string                      `json:"cargo_lock_hash"`
	MaxDurationSeconds        int                         `json:"max_duration_seconds"`
	MaxOutputBytes            int                         `json:"max_output_bytes"`
	StartedAt                 time.Time                   `json:"started_at"`
	CompletedAt               time.Time                   `json:"completed_at"`
	DurationMS                int64                       `json:"duration_ms"`
	Status                    string                      `json:"status"`
	ExitCode                  *int                        `json:"exit_code,omitempty"`
	TerminationReason         string                      `json:"termination_reason"`
	Stdout                    string                      `json:"stdout"`
	Stderr                    string                      `json:"stderr"`
	StdoutHash                string                      `json:"stdout_hash"`
	StderrHash                string                      `json:"stderr_hash"`
	StdoutTruncated           bool                        `json:"stdout_truncated"`
	StderrTruncated           bool                        `json:"stderr_truncated"`
	EvidenceRefs              []string                    `json:"evidence_refs"`
	Limitations               []string                    `json:"limitations"`
	NetworkAccess             bool                        `json:"network_access"`
	DependencyResolution      bool                        `json:"dependency_resolution"`
	WalletMaterialAccessed    bool                        `json:"wallet_material_accessed"`
	MainnetRPCAccessed        bool                        `json:"mainnet_rpc_accessed"`
	MainnetTransactionSent    bool                        `json:"mainnet_transaction_sent"`
	SourceExecuted            bool                        `json:"source_executed"`
	HarnessExecuted           bool                        `json:"harness_executed"`
	ResultHash                string                      `json:"result_hash"`
	VerdictAuthority          bool                        `json:"verdict_authority"`
	CreatedAt                 time.Time                   `json:"created_at"`
}

// PrepareLiteSVMExecution performs the mandatory fail-closed evidence checks
// immediately before a worker command launch. It does not create a process.
func PrepareLiteSVMExecution(ctx context.Context, db *sql.DB, jobRef, profileRef, materializationRef, workerID, workerImageDigest string) (LiteSVMExecutionPlan, error) {
	if db == nil {
		return LiteSVMExecutionPlan{}, errors.New("database unavailable")
	}
	jobRef = strings.TrimSpace(jobRef)
	profileRef = strings.TrimSpace(profileRef)
	materializationRef = strings.TrimSpace(materializationRef)
	workerID = strings.TrimSpace(workerID)
	workerImageDigest = normalizeDefenseSHA256Digest(workerImageDigest)
	if jobRef == "" || profileRef == "" || materializationRef == "" || workerID == "" || workerImageDigest == "" {
		return LiteSVMExecutionPlan{}, errors.New("job, profile, materialization and live worker identity are required")
	}
	job, err := GetWorkerJob(ctx, db, jobRef)
	if err != nil {
		return LiteSVMExecutionPlan{}, err
	}
	if job.Action != WorkerActionRunLiteSVMHarness {
		return LiteSVMExecutionPlan{}, errors.New("worker job is not a LiteSVM harness execution")
	}
	profile, err := AuthorizeHarnessExecution(ctx, db, profileRef, workerID, workerImageDigest)
	if err != nil {
		return LiteSVMExecutionPlan{}, err
	}
	if profile.Engine != HarnessEngineLiteSVM || !fixedLiteSVMProfileCommand(profile.CommandPolicy) {
		return LiteSVMExecutionPlan{}, errors.New("execution profile does not contain the fixed LiteSVM command policy")
	}
	materialization, err := LoadHarnessMaterialization(ctx, db, materializationRef)
	if err != nil {
		return LiteSVMExecutionPlan{}, errors.New("harness materialization not found")
	}
	if materialization.ProfileRef != profile.ProfileRef || materialization.ProgramID != profile.ProgramID || materialization.Network != profile.Network || materialization.Engine != HarnessEngineLiteSVM {
		return LiteSVMExecutionPlan{}, errors.New("materialization does not match the execution profile")
	}
	if materialization.Status != "ready" || materialization.NetworkAccess || materialization.DependencyResolution || materialization.SourceExecuted || materialization.HarnessExecuted || materialization.MainnetTransactionSent || materialization.VerdictAuthority {
		return LiteSVMExecutionPlan{}, errors.New("materialization is not a ready non-executed LiteSVM input")
	}
	sourceArtifact, err := LoadArtifact(ctx, db, materialization.SourceHarnessArtifactRef)
	if err != nil {
		return LiteSVMExecutionPlan{}, errors.New("source harness artifact not found")
	}
	materializedArtifact, err := LoadArtifact(ctx, db, materialization.MaterializedArtifactRef)
	if err != nil {
		return LiteSVMExecutionPlan{}, errors.New("materialized harness artifact not found")
	}
	if job.SourceArtifactRef != materializedArtifact.ArtifactRef {
		return LiteSVMExecutionPlan{}, errors.New("worker job materialized artifact does not match the materialization")
	}
	bundle, err := validateMaterializedHarnessForExecution(profile, materialization, sourceArtifact, materializedArtifact)
	if err != nil {
		return LiteSVMExecutionPlan{}, err
	}

	executables := make([]LiteSVMExecutableEvidence, 0, len(profile.ToolPins)+1)
	toolRefs := make([]string, 0, len(profile.ToolPins)+1)
	cargoPath, cargoHash, rustcPath := "", "", ""
	for _, pin := range profile.ToolPins {
		evidence := executableEvidenceFromPin(pin)
		executables = append(executables, evidence)
		toolRefs = append(toolRefs, evidence.AttestationRef)
		switch evidence.ToolName {
		case "cargo":
			cargoPath, cargoHash = evidence.BinaryPath, evidence.BinaryHash
		case "rustc":
			rustcPath = evidence.BinaryPath
		}
	}
	bwrapEvidence, err := authorizeLiveSandboxExecutable(ctx, db, workerID, workerImageDigest)
	if err != nil {
		return LiteSVMExecutionPlan{}, err
	}
	executables = append(executables, bwrapEvidence)
	toolRefs = append(toolRefs, bwrapEvidence.AttestationRef)
	sort.Slice(executables, func(i, j int) bool { return executables[i].ToolName < executables[j].ToolName })
	toolRefs = uniqueStrings(toolRefs)
	if cargoPath == "" || rustcPath == "" || normalizeDefenseSHA256Digest(cargoHash) == "" {
		return LiteSVMExecutionPlan{}, errors.New("pinned Cargo/Rust executable evidence is missing")
	}

	toolDirs := []string{}
	for _, evidence := range executables {
		if evidence.BinaryPath == "" || !filepath.IsAbs(evidence.BinaryPath) {
			return LiteSVMExecutionPlan{}, fmt.Errorf("pinned tool path is not absolute: %s", evidence.ToolName)
		}
		toolDirs = append(toolDirs, filepath.Dir(evidence.BinaryPath))
	}
	toolDirs = uniqueStrings(toolDirs)
	sort.Strings(toolDirs)
	environmentTemplate := map[string]string{
		"CARGO_HOME":               "/tmp/koschei-scratch/cargo-home",
		"CARGO_NET_OFFLINE":        "true",
		"CARGO_TARGET_DIR":         "/tmp/koschei-scratch/target",
		"CARGO_TERM_COLOR":         "never",
		"GIT_CONFIG_NOSYSTEM":      "1",
		"GIT_TERMINAL_PROMPT":      "0",
		"HOME":                     "/tmp/koschei-scratch/home",
		"KOSCHEI_DEFENSE_ISOLATED": "1",
		"LANG":                     "C.UTF-8",
		"LC_ALL":                   "C.UTF-8",
		"PATH":                     strings.Join(toolDirs, ":"),
		"RUST_BACKTRACE":           "0",
		"RUSTC":                    rustcPath,
		"RUSTUP_HOME":              "/tmp/koschei-scratch/rustup-home",
		"SOURCE_DATE_EPOCH":        "0",
		"TERM":                     "dumb",
		"TMPDIR":                   "/tmp/koschei-scratch/tmp",
		"TZ":                       "UTC",
	}
	commandArgv := append([]string(nil), fixedLiteSVMCommandArgv...)
	commandHash := hashValue(commandArgv)
	sandboxPolicy := liteSVMBubblewrapPolicy(environmentTemplate, cargoPath, bwrapEvidence.BinaryPath)
	sandboxPolicyHash := hashValue(sandboxPolicy)
	environmentHash := hashValue(environmentTemplate)
	inputHash := hashValue(map[string]any{
		"profile_ref":                profile.ProfileRef,
		"profile_hash":               profile.ProfileHash,
		"materialization_ref":        materialization.MaterializationRef,
		"materialization_hash":       materialization.MaterializationHash,
		"source_artifact_ref":        sourceArtifact.ArtifactRef,
		"source_artifact_hash":       sourceArtifact.ContentHash,
		"materialized_artifact_ref":  materializedArtifact.ArtifactRef,
		"materialized_artifact_hash": materializedArtifact.ContentHash,
		"cargo_manifest_hash":        materialization.CargoManifestHash,
		"cargo_lock_hash":            materialization.CargoLockHash,
		"worker_id":                  workerID,
		"worker_image_digest":        workerImageDigest,
		"executable_evidence":        executables,
		"command_hash":               commandHash,
		"sandbox_policy_hash":        sandboxPolicyHash,
		"environment_hash":           environmentHash,
	})
	return LiteSVMExecutionPlan{
		JobRef: job.JobRef, Profile: profile, Materialization: materialization,
		SourceHarnessArtifact: sourceArtifact, MaterializedArtifact: materializedArtifact, Bundle: bundle,
		CommandArgv: commandArgv, CommandHash: commandHash, SandboxPolicy: sandboxPolicy,
		SandboxPolicyHash: sandboxPolicyHash, EnvironmentTemplate: environmentTemplate,
		EnvironmentHash: environmentHash, InputHash: inputHash, ToolAttestationRefs: toolRefs,
		ExecutableEvidence: executables, CargoExecutablePath: cargoPath, CargoExecutableHash: cargoHash,
		SandboxExecutablePath: bwrapEvidence.BinaryPath, SandboxExecutableHash: bwrapEvidence.BinaryHash,
		MaxDurationSeconds: profile.MaxDurationSeconds, MaxOutputBytes: profile.MaxOutputBytes,
		NetworkAccess: false, DependencyResolution: false, WalletMaterialAccessed: false,
		MainnetRPCAccessed: false, MainnetTransactionSent: false, VerdictAuthority: false,
	}, nil
}

func executableEvidenceFromPin(pin HarnessToolPin) LiteSVMExecutableEvidence {
	return LiteSVMExecutableEvidence{
		ToolName: strings.TrimSpace(pin.ToolName), AttestationRef: strings.TrimSpace(pin.AttestationRef),
		VersionHash: pin.VersionHash, BinaryPath: pin.BinaryPath, BinaryHash: pin.BinaryHash,
		WorkerImageDigest: pin.WorkerImageDigest,
	}
}

func authorizeLiveSandboxExecutable(ctx context.Context, db *sql.DB, workerID, workerImageDigest string) (LiteSVMExecutableEvidence, error) {
	attestation, err := loadLatestPinnedToolAttestation(ctx, db, workerID, "bwrap")
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return LiteSVMExecutableEvidence{}, errors.New("pinned bubblewrap attestation is unavailable")
		}
		return LiteSVMExecutableEvidence{}, err
	}
	if !attestation.Available || !attestation.Pinned || attestation.WorkerImageDigest != workerImageDigest ||
		normalizeDefenseSHA256Digest(attestation.VersionHash) == "" || normalizeDefenseSHA256Digest(attestation.BinaryHash) == "" ||
		strings.TrimSpace(attestation.BinaryPath) == "" {
		return LiteSVMExecutableEvidence{}, errors.New("pinned bubblewrap evidence does not match the live worker image")
	}
	resolved, err := exec.LookPath("bwrap")
	if err != nil || strings.TrimSpace(resolved) == "" {
		return LiteSVMExecutableEvidence{}, errors.New("bubblewrap cannot be resolved at execution time")
	}
	if filepath.Clean(resolved) != filepath.Clean(attestation.BinaryPath) {
		return LiteSVMExecutableEvidence{}, errors.New("bubblewrap resolved path changed after attestation")
	}
	currentHash, err := hashDefenseExecutable(resolved)
	if err != nil || currentHash != attestation.BinaryHash {
		return LiteSVMExecutableEvidence{}, errors.New("bubblewrap executable hash changed after attestation")
	}
	return LiteSVMExecutableEvidence{
		ToolName: "bwrap", AttestationRef: attestation.AttestationRef, VersionHash: attestation.VersionHash,
		BinaryPath: attestation.BinaryPath, BinaryHash: attestation.BinaryHash,
		WorkerImageDigest: attestation.WorkerImageDigest,
	}, nil
}

func liteSVMBubblewrapPolicy(environment map[string]string, cargoPath, bwrapPath string) map[string]any {
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	setEnv := make([]map[string]string, 0, len(keys))
	for _, key := range keys {
		setEnv = append(setEnv, map[string]string{"name": key, "value": environment[key]})
	}
	return map[string]any{
		"policy_version":               liteSVMSandboxPolicyVersion,
		"launcher":                     bwrapPath,
		"logical_command":              append([]string(nil), fixedLiteSVMCommandArgv...),
		"cargo_executable":             cargoPath,
		"unshare_all":                  true,
		"new_session":                  true,
		"die_with_parent":              true,
		"clear_environment":            true,
		"read_only_root":               true,
		"host_work_root_masked":        true,
		"new_proc_mount":               true,
		"new_device_mount":             true,
		"ephemeral_tmp":                true,
		"input_mount":                  map[string]string{"source": "$INPUT", "destination": "/tmp/koschei-workspace", "mode": "read_only"},
		"scratch_mount":                map[string]string{"source": "$SCRATCH", "destination": "/tmp/koschei-scratch", "mode": "read_write"},
		"working_directory":            "/tmp/koschei-workspace",
		"environment":                  setEnv,
		"network_namespace":            "isolated",
		"pid_namespace":                "isolated",
		"parent_environment_inherited": false,
		"shell":                        false,
	}
}

func validateMaterializedHarnessForExecution(profile HarnessExecutionProfile, materialization HarnessMaterialization, sourceArtifact, materializedArtifact Artifact) (map[string]string, error) {
	if materializedArtifact.ArtifactType != "source_bundle" || materializedArtifact.ProgramID != profile.ProgramID || materializedArtifact.Network != profile.Network {
		return nil, errors.New("materialized artifact identity does not match the execution profile")
	}
	if materializedArtifact.ContentHash != materialization.MaterializedBundleHash {
		return nil, errors.New("materialized artifact content hash does not match the materialization")
	}
	if sourceArtifact.ArtifactRef != materialization.SourceHarnessArtifactRef || sourceArtifact.ProgramID != profile.ProgramID || sourceArtifact.Network != profile.Network {
		return nil, errors.New("source harness artifact identity does not match the materialization")
	}
	if strings.ToLower(harnessArtifactMetadataString(materializedArtifact.Metadata, "artifact_role")) != "materialized_harness" ||
		harnessArtifactMetadataString(materializedArtifact.Metadata, "harness_profile_ref") != profile.ProfileRef ||
		harnessArtifactMetadataString(materializedArtifact.Metadata, "source_harness_artifact_ref") != sourceArtifact.ArtifactRef ||
		strings.ToLower(harnessArtifactMetadataString(materializedArtifact.Metadata, "engine")) != HarnessEngineLiteSVM {
		return nil, errors.New("materialized artifact metadata does not match the execution profile")
	}
	bundle, err := decodeSourceBundle(materializedArtifact.Content)
	if err != nil {
		return nil, err
	}
	if len(bundle) != materialization.FileCount || len(materialization.FileManifest) != materialization.FileCount {
		return nil, errors.New("materialized artifact file count does not match the immutable file manifest")
	}
	manifestByPath := make(map[string]HarnessMaterializedFile, len(materialization.FileManifest))
	for _, file := range materialization.FileManifest {
		clean, pathErr := safeRelativePath(file.Path)
		if pathErr != nil || clean != file.Path || manifestByPath[clean].Path != "" {
			return nil, errors.New("materialization contains an invalid or duplicate file path")
		}
		manifestByPath[clean] = file
	}
	totalBytes := 0
	for path, content := range bundle {
		file, ok := manifestByPath[path]
		if !ok || file.SizeBytes != len(content) || file.ContentHash != hashMaterializationBytes([]byte(content)) {
			return nil, fmt.Errorf("materialized file evidence mismatch: %s", path)
		}
		totalBytes += len(content)
	}
	if totalBytes != materialization.TotalBytes {
		return nil, errors.New("materialized artifact byte count does not match the materialization")
	}
	if hashMaterializationBytes([]byte(bundle["Cargo.toml"])) != materialization.CargoManifestHash ||
		hashMaterializationBytes([]byte(bundle["Cargo.lock"])) != materialization.CargoLockHash {
		return nil, errors.New("materialized Cargo manifest or lock hash mismatch")
	}
	manifestContent, ok := bundle[materializationManifestPath]
	if !ok {
		return nil, errors.New("materialized harness manifest is missing")
	}
	var generated harnessMaterializationManifest
	if json.Unmarshal([]byte(manifestContent), &generated) != nil || generated.ProfileRef != profile.ProfileRef ||
		generated.ProfileHash != profile.ProfileHash || generated.SourceHarnessArtifactRef != sourceArtifact.ArtifactRef ||
		generated.SourceHarnessArtifactHash != sourceArtifact.ContentHash || generated.ProgramID != profile.ProgramID ||
		generated.Network != profile.Network || generated.Engine != HarnessEngineLiteSVM || generated.NetworkAccess ||
		generated.DependencyResolution || generated.SourceExecuted || generated.HarnessExecuted ||
		generated.MainnetTransactionSent || generated.VerdictAuthority {
		return nil, errors.New("generated materialization manifest does not match the immutable execution evidence")
	}
	return bundle, nil
}

func fixedLiteSVMProfileCommand(policy map[string]any) bool {
	if strings.ToLower(strings.TrimSpace(fmt.Sprint(policy["engine"]))) != HarnessEngineLiteSVM ||
		strings.TrimSpace(fmt.Sprint(policy["policy_version"])) != "koschei-harness-command-policy-v1" {
		return false
	}
	commands := []string{}
	switch raw := policy["commands"].(type) {
	case []string:
		commands = append(commands, raw...)
	case []any:
		for _, value := range raw {
			commands = append(commands, strings.TrimSpace(fmt.Sprint(value)))
		}
	default:
		return false
	}
	return len(commands) == 1 && commands[0] == "cargo test --locked --offline" &&
		policyBoolFalse(policy, "arbitrary_commands") && policyBoolFalse(policy, "network_access") &&
		policyBoolFalse(policy, "wallet_keys") && policyBoolFalse(policy, "mainnet_rpc") &&
		policyBoolFalse(policy, "mainnet_transaction_sent")
}

func policyBoolFalse(policy map[string]any, key string) bool {
	value, ok := policy[key]
	if !ok {
		return false
	}
	parsed, ok := value.(bool)
	return ok && !parsed
}

// PersistLiteSVMExecutionAttempt stores one append-only Phase 12C result. The
// deterministic result hash excludes attempt identity and timestamps.
func PersistLiteSVMExecutionAttempt(ctx context.Context, db *sql.DB, plan LiteSVMExecutionPlan, outcome LiteSVMExecutionOutcome) (LiteSVMExecutionAttempt, error) {
	if db == nil {
		return LiteSVMExecutionAttempt{}, errors.New("database unavailable")
	}
	if plan.JobRef == "" || plan.Profile.ProfileRef == "" || plan.Materialization.MaterializationRef == "" ||
		plan.MaterializedArtifact.ArtifactRef == "" || len(plan.SandboxPolicy) == 0 ||
		plan.SandboxPolicyHash == "" || plan.SandboxPolicyHash != hashValue(plan.SandboxPolicy) {
		return LiteSVMExecutionAttempt{}, errors.New("LiteSVM execution plan is incomplete")
	}
	outcome.Status = strings.ToLower(strings.TrimSpace(outcome.Status))
	outcome.TerminationReason = strings.TrimSpace(outcome.TerminationReason)
	if outcome.AttemptNumber <= 0 || outcome.TerminationReason == "" {
		return LiteSVMExecutionAttempt{}, errors.New("attempt number and termination reason are required")
	}
	validStatus := map[string]bool{"rejected": true, "completed": true, "failed": true, "timed_out": true, "cancelled": true}
	if !validStatus[outcome.Status] {
		return LiteSVMExecutionAttempt{}, errors.New("unsupported LiteSVM attempt status")
	}
	if outcome.StartedAt.IsZero() {
		outcome.StartedAt = time.Now().UTC()
	}
	if outcome.CompletedAt.IsZero() {
		outcome.CompletedAt = outcome.StartedAt
	}
	outcome.StartedAt = outcome.StartedAt.UTC()
	outcome.CompletedAt = outcome.CompletedAt.UTC()
	if outcome.CompletedAt.Before(outcome.StartedAt) {
		return LiteSVMExecutionAttempt{}, errors.New("execution completion precedes execution start")
	}
	if outcome.Status == "rejected" {
		if outcome.SourceExecuted || outcome.HarnessExecuted {
			return LiteSVMExecutionAttempt{}, errors.New("rejected attempt cannot report source execution")
		}
		outcome.SourceExecuted = false
		outcome.HarnessExecuted = false
	} else if !outcome.SourceExecuted || !outcome.HarnessExecuted {
		return LiteSVMExecutionAttempt{}, errors.New("launched attempt must report source and harness execution")
	}
	stdout, stdoutTruncated := boundLiteSVMOutput(outcome.Stdout, plan.MaxOutputBytes)
	stderr, stderrTruncated := boundLiteSVMOutput(outcome.Stderr, plan.MaxOutputBytes)
	outcome.StdoutTruncated = outcome.StdoutTruncated || stdoutTruncated
	outcome.StderrTruncated = outcome.StderrTruncated || stderrTruncated
	stdoutHash := hashMaterializationBytes([]byte(stdout))
	stderrHash := hashMaterializationBytes([]byte(stderr))
	durationMS := outcome.CompletedAt.Sub(outcome.StartedAt).Milliseconds()
	limitations := uniqueStrings(outcome.Limitations)
	evidenceRefs := uniqueStrings(append([]string{
		"defense_worker_job:" + plan.JobRef,
		"harness_execution_profile:" + plan.Profile.ProfileRef,
		"harness_materialization:" + plan.Materialization.MaterializationRef,
		"artifact:" + plan.SourceHarnessArtifact.ArtifactRef,
		"artifact:" + plan.MaterializedArtifact.ArtifactRef,
		"sandbox_policy:" + plan.SandboxPolicyHash,
	}, prefixedEvidenceRefs("toolchain_attestation:", plan.ToolAttestationRefs)...))
	resultPayload := map[string]any{
		"schema_version":             "koschei-litesvm-execution-result-v1",
		"profile_hash":               plan.Profile.ProfileHash,
		"materialization_hash":       plan.Materialization.MaterializationHash,
		"source_artifact_hash":       plan.SourceHarnessArtifact.ContentHash,
		"materialized_artifact_hash": plan.MaterializedArtifact.ContentHash,
		"worker_id":                  plan.Profile.WorkerID,
		"worker_image_digest":        plan.Profile.WorkerImageDigest,
		"executable_evidence":        plan.ExecutableEvidence,
		"command_hash":               plan.CommandHash,
		"sandbox_policy_hash":        plan.SandboxPolicyHash,
		"environment_hash":           plan.EnvironmentHash,
		"input_hash":                 plan.InputHash,
		"status":                     outcome.Status,
		"exit_code":                  outcome.ExitCode,
		"termination_reason":         outcome.TerminationReason,
		"stdout_hash":                stdoutHash,
		"stderr_hash":                stderrHash,
		"stdout_truncated":           outcome.StdoutTruncated,
		"stderr_truncated":           outcome.StderrTruncated,
		"limitations":                limitations,
		"network_access":             false,
		"dependency_resolution":      false,
		"wallet_material_accessed":   false,
		"mainnet_rpc_accessed":       false,
		"mainnet_transaction_sent":   false,
		"source_executed":            outcome.SourceExecuted,
		"harness_executed":           outcome.HarnessExecuted,
		"verdict_authority":          false,
	}
	resultHash := hashJSON(resultPayload)
	identityPayload := map[string]any{
		"job_ref":        plan.JobRef,
		"attempt_number": outcome.AttemptNumber,
		"started_at":     outcome.StartedAt.Format(time.RFC3339Nano),
		"result_hash":    resultHash,
	}
	attemptRef := prefixedID("KLSE1-", identityPayload)
	toolRefsRaw, _ := json.Marshal(plan.ToolAttestationRefs)
	executablesRaw, _ := json.Marshal(plan.ExecutableEvidence)
	argvRaw, _ := json.Marshal(plan.CommandArgv)
	sandboxRaw, _ := json.Marshal(plan.SandboxPolicy)
	evidenceRaw, _ := json.Marshal(evidenceRefs)
	limitationsRaw, _ := json.Marshal(limitations)
	var exitCode any
	if outcome.ExitCode != nil {
		exitCode = *outcome.ExitCode
	}
	_, err := db.ExecContext(ctx, `INSERT INTO defense_litesvm_execution_attempts
		(attempt_ref,attempt_version,job_ref,attempt_number,profile_ref,profile_hash,materialization_ref,materialization_hash,
		 source_harness_artifact_ref,source_harness_artifact_hash,materialized_artifact_ref,materialized_artifact_hash,
		 program_id,network,engine,worker_id,worker_image_digest,tool_attestation_refs,executable_evidence,command_argv,
		 command_hash,sandbox_policy,sandbox_policy_hash,environment_hash,input_hash,cargo_manifest_hash,cargo_lock_hash,
		 max_duration_seconds,max_output_bytes,started_at,completed_at,duration_ms,status,exit_code,termination_reason,
		 stdout_text,stderr_text,stdout_hash,stderr_hash,stdout_truncated,stderr_truncated,evidence_refs,limitations,
		 network_access,dependency_resolution,wallet_material_accessed,mainnet_rpc_accessed,mainnet_transaction_sent,
		 source_executed,harness_executed,result_hash,verdict_authority,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'litesvm',$15,$16,$17::jsonb,$18::jsonb,$19::jsonb,
		 $20,$21::jsonb,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41::jsonb,$42::jsonb,
		 false,false,false,false,false,$43,$44,$45,false,'defense-worker')
		ON CONFLICT(attempt_ref) DO NOTHING`,
		attemptRef, LiteSVMExecutionAttemptVersion, plan.JobRef, outcome.AttemptNumber, plan.Profile.ProfileRef,
		plan.Profile.ProfileHash, plan.Materialization.MaterializationRef, plan.Materialization.MaterializationHash,
		plan.SourceHarnessArtifact.ArtifactRef, plan.SourceHarnessArtifact.ContentHash, plan.MaterializedArtifact.ArtifactRef,
		plan.MaterializedArtifact.ContentHash, plan.Profile.ProgramID, plan.Profile.Network, plan.Profile.WorkerID,
		plan.Profile.WorkerImageDigest, string(toolRefsRaw), string(executablesRaw), string(argvRaw), plan.CommandHash,
		string(sandboxRaw), plan.SandboxPolicyHash, plan.EnvironmentHash, plan.InputHash, plan.Materialization.CargoManifestHash,
		plan.Materialization.CargoLockHash, plan.MaxDurationSeconds, plan.MaxOutputBytes, outcome.StartedAt,
		outcome.CompletedAt, durationMS, outcome.Status, exitCode, outcome.TerminationReason, stdout, stderr, stdoutHash,
		stderrHash, outcome.StdoutTruncated, outcome.StderrTruncated, string(evidenceRaw), string(limitationsRaw),
		outcome.SourceExecuted, outcome.HarnessExecuted, resultHash)
	if err != nil {
		return LiteSVMExecutionAttempt{}, err
	}
	return LoadLiteSVMExecutionAttempt(ctx, db, attemptRef)
}

func LoadLiteSVMExecutionAttempt(ctx context.Context, db *sql.DB, attemptRef string) (LiteSVMExecutionAttempt, error) {
	if db == nil {
		return LiteSVMExecutionAttempt{}, errors.New("database unavailable")
	}
	var item LiteSVMExecutionAttempt
	var toolRefsRaw, executablesRaw, argvRaw, sandboxRaw, evidenceRaw, limitationsRaw []byte
	var exitCode sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT attempt_ref,attempt_version,job_ref,attempt_number,profile_ref,profile_hash,
		materialization_ref,materialization_hash,source_harness_artifact_ref,source_harness_artifact_hash,
		materialized_artifact_ref,materialized_artifact_hash,program_id,network,engine,worker_id,worker_image_digest,
		tool_attestation_refs,executable_evidence,command_argv,command_hash,sandbox_policy,sandbox_policy_hash,
		environment_hash,input_hash,cargo_manifest_hash,cargo_lock_hash,max_duration_seconds,max_output_bytes,
		started_at,completed_at,duration_ms,status,exit_code,termination_reason,stdout_text,stderr_text,stdout_hash,
		stderr_hash,stdout_truncated,stderr_truncated,evidence_refs,limitations,network_access,dependency_resolution,
		wallet_material_accessed,mainnet_rpc_accessed,mainnet_transaction_sent,source_executed,harness_executed,
		result_hash,verdict_authority,created_at
		FROM defense_litesvm_execution_attempts WHERE attempt_ref=$1`, strings.TrimSpace(attemptRef)).Scan(
		&item.AttemptRef, &item.AttemptVersion, &item.JobRef, &item.AttemptNumber, &item.ProfileRef, &item.ProfileHash,
		&item.MaterializationRef, &item.MaterializationHash, &item.SourceHarnessArtifactRef, &item.SourceHarnessArtifactHash,
		&item.MaterializedArtifactRef, &item.MaterializedArtifactHash, &item.ProgramID, &item.Network, &item.Engine,
		&item.WorkerID, &item.WorkerImageDigest, &toolRefsRaw, &executablesRaw, &argvRaw, &item.CommandHash,
		&sandboxRaw, &item.SandboxPolicyHash, &item.EnvironmentHash, &item.InputHash, &item.CargoManifestHash,
		&item.CargoLockHash, &item.MaxDurationSeconds, &item.MaxOutputBytes, &item.StartedAt, &item.CompletedAt,
		&item.DurationMS, &item.Status, &exitCode, &item.TerminationReason, &item.Stdout, &item.Stderr,
		&item.StdoutHash, &item.StderrHash, &item.StdoutTruncated, &item.StderrTruncated, &evidenceRaw,
		&limitationsRaw, &item.NetworkAccess, &item.DependencyResolution, &item.WalletMaterialAccessed,
		&item.MainnetRPCAccessed, &item.MainnetTransactionSent, &item.SourceExecuted, &item.HarnessExecuted,
		&item.ResultHash, &item.VerdictAuthority, &item.CreatedAt)
	if err != nil {
		return LiteSVMExecutionAttempt{}, err
	}
	if exitCode.Valid {
		value := int(exitCode.Int64)
		item.ExitCode = &value
	}
	_ = json.Unmarshal(toolRefsRaw, &item.ToolAttestationRefs)
	_ = json.Unmarshal(executablesRaw, &item.ExecutableEvidence)
	_ = json.Unmarshal(argvRaw, &item.CommandArgv)
	_ = json.Unmarshal(sandboxRaw, &item.SandboxPolicy)
	_ = json.Unmarshal(evidenceRaw, &item.EvidenceRefs)
	_ = json.Unmarshal(limitationsRaw, &item.Limitations)
	return item, nil
}

func ListLiteSVMExecutionAttempts(ctx context.Context, db *sql.DB, jobRef, profileRef, materializationRef string, limit int) ([]LiteSVMExecutionAttempt, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT attempt_ref FROM defense_litesvm_execution_attempts
		WHERE ($1='' OR job_ref=$1) AND ($2='' OR profile_ref=$2) AND ($3='' OR materialization_ref=$3)
		ORDER BY created_at DESC LIMIT $4`, strings.TrimSpace(jobRef), strings.TrimSpace(profileRef), strings.TrimSpace(materializationRef), limit)
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
	out := make([]LiteSVMExecutionAttempt, 0, len(refs))
	for _, ref := range refs {
		item, err := LoadLiteSVMExecutionAttempt(ctx, db, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func boundLiteSVMOutput(value string, maximum int) (string, bool) {
	if maximum <= 0 || maximum > 1024*1024 {
		maximum = 256 * 1024
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= maximum {
		return value, false
	}
	data := []byte(value[:maximum])
	for len(data) > 0 && !utf8.Valid(data) {
		data = data[:len(data)-1]
	}
	return string(data), true
}

func prefixedEvidenceRefs(prefix string, values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, prefix+value)
		}
	}
	return out
}
