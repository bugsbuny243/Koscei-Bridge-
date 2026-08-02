package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	ToolchainPolicyVersion = "v1.0.0"
	SafeManifestVersion    = "v1.0.0"
)

var sha256EvidencePattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var phase12RequiredTools = []string{"anchor", "cargo", "litesvm", "rustc", "solana"}

type ToolchainPolicyInput struct {
	WorkerImageDigest string            `json:"worker_image_digest"`
	RequiredTools     map[string]string `json:"required_tools"`
}

type ToolchainPolicy struct {
	PolicyRef         string            `json:"policy_ref"`
	PolicyVersion     string            `json:"policy_version"`
	WorkerImageDigest string            `json:"worker_image_digest"`
	RequiredTools     map[string]string `json:"required_tools"`
	PolicyHash        string            `json:"policy_hash"`
	VerdictAuthority  bool              `json:"verdict_authority"`
	CreatedAt         time.Time         `json:"created_at"`
}

type ToolchainPolicyEvaluation struct {
	PolicyRef           string   `json:"policy_ref"`
	WorkerID            string   `json:"worker_id"`
	WorkerImageDigest   string   `json:"worker_image_digest"`
	ExecutionAuthorized bool     `json:"execution_authorized"`
	Status              string   `json:"status"`
	MatchedTools        []string `json:"matched_tools"`
	MissingTools        []string `json:"missing_tools"`
	MismatchedTools     []string `json:"mismatched_tools"`
	EvidenceRefs        []string `json:"evidence_refs"`
	Limitations         []string `json:"limitations"`
	VerdictAuthority    bool     `json:"verdict_authority"`
}

func CreateToolchainPolicy(ctx context.Context, db *sql.DB, input ToolchainPolicyInput) (ToolchainPolicy, error) {
	if db == nil {
		return ToolchainPolicy{}, errors.New("database unavailable")
	}
	input.WorkerImageDigest = strings.TrimSpace(input.WorkerImageDigest)
	tools, err := normalizeToolchainPolicyTools(input.RequiredTools)
	if err != nil {
		return ToolchainPolicy{}, err
	}
	if !sha256EvidencePattern.MatchString(input.WorkerImageDigest) {
		return ToolchainPolicy{}, errors.New("worker_image_digest must be sha256:<64 lowercase hex>")
	}

	payload := map[string]any{
		"schema_version":      "koschei-defense-toolchain-policy-v1",
		"policy_version":      ToolchainPolicyVersion,
		"worker_image_digest": input.WorkerImageDigest,
		"required_tools":      tools,
	}
	now := time.Now().UTC()
	policy := ToolchainPolicy{
		PolicyRef:         prefixedID("KTP1-", payload),
		PolicyVersion:     ToolchainPolicyVersion,
		WorkerImageDigest: input.WorkerImageDigest,
		RequiredTools:     tools,
		PolicyHash:        hashJSON(payload),
		VerdictAuthority:  false,
		CreatedAt:         now,
	}
	toolsRaw, _ := json.Marshal(tools)
	_, err = db.ExecContext(ctx, `INSERT INTO defense_toolchain_policies
		(policy_ref,policy_version,worker_image_digest,required_tools,policy_hash,verdict_authority,created_by,created_at)
		VALUES($1,$2,$3,$4::jsonb,$5,false,'owner',$6)
		ON CONFLICT(policy_ref) DO NOTHING`, policy.PolicyRef, policy.PolicyVersion, policy.WorkerImageDigest,
		string(toolsRaw), policy.PolicyHash, policy.CreatedAt)
	if err != nil {
		return ToolchainPolicy{}, err
	}
	return policy, nil
}

func EvaluateToolchainPolicy(policy ToolchainPolicy, workerID, workerImageDigest string, attestations []ToolchainAttestation) ToolchainPolicyEvaluation {
	workerID = strings.TrimSpace(workerID)
	workerImageDigest = strings.TrimSpace(workerImageDigest)
	result := ToolchainPolicyEvaluation{
		PolicyRef:         policy.PolicyRef,
		WorkerID:          workerID,
		WorkerImageDigest: workerImageDigest,
		Status:            "toolchain_mismatch",
		VerdictAuthority:  false,
	}
	if workerID == "" {
		result.Limitations = append(result.Limitations, "Worker identity is missing.")
	}
	if workerImageDigest == "" || workerImageDigest != policy.WorkerImageDigest {
		result.Limitations = append(result.Limitations, "Worker image digest does not match the pinned policy.")
	}

	latest := latestToolchainAttestations(workerID, attestations)
	for _, tool := range phase12RequiredTools {
		expected := policy.RequiredTools[tool]
		observed, ok := latest[tool]
		if !ok || !observed.Available {
			result.MissingTools = append(result.MissingTools, tool)
			continue
		}
		result.EvidenceRefs = append(result.EvidenceRefs, "toolchain:"+observed.AttestationRef)
		if observed.VersionHash != expected {
			result.MismatchedTools = append(result.MismatchedTools, tool)
			continue
		}
		result.MatchedTools = append(result.MatchedTools, tool)
	}

	sort.Strings(result.MatchedTools)
	sort.Strings(result.MissingTools)
	sort.Strings(result.MismatchedTools)
	result.EvidenceRefs = uniqueStrings(result.EvidenceRefs)
	if len(result.MissingTools) > 0 {
		result.Limitations = append(result.Limitations, "One or more required tools are unavailable or unattested.")
	}
	if len(result.MismatchedTools) > 0 {
		result.Limitations = append(result.Limitations, "One or more tool version hashes differ from the pinned policy.")
	}
	if workerID != "" && workerImageDigest == policy.WorkerImageDigest && len(result.MissingTools) == 0 && len(result.MismatchedTools) == 0 {
		result.ExecutionAuthorized = true
		result.Status = "pinned_toolchain_verified"
		result.Limitations = []string{
			"Toolchain verification authorizes manifest preparation only; source execution remains controlled by separate feature gates and worker sandbox policy.",
		}
	}
	return result
}

func normalizeToolchainPolicyTools(input map[string]string) (map[string]string, error) {
	if len(input) != len(phase12RequiredTools) {
		return nil, fmt.Errorf("required_tools must contain exactly: %s", strings.Join(phase12RequiredTools, ", "))
	}
	allowed := make(map[string]struct{}, len(phase12RequiredTools))
	for _, tool := range phase12RequiredTools {
		allowed[tool] = struct{}{}
	}
	out := make(map[string]string, len(input))
	for rawName, rawHash := range input {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if _, ok := allowed[name]; !ok {
			return nil, fmt.Errorf("unsupported or unexpected tool %q", rawName)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("duplicate tool %q", name)
		}
		versionHash := strings.TrimSpace(rawHash)
		if !sha256EvidencePattern.MatchString(versionHash) {
			return nil, fmt.Errorf("tool %s version hash must be sha256:<64 lowercase hex>", name)
		}
		out[name] = versionHash
	}
	for _, tool := range phase12RequiredTools {
		if _, ok := out[tool]; !ok {
			return nil, fmt.Errorf("required tool %s is missing", tool)
		}
	}
	return out, nil
}

func latestToolchainAttestations(workerID string, attestations []ToolchainAttestation) map[string]ToolchainAttestation {
	out := map[string]ToolchainAttestation{}
	for _, item := range attestations {
		if strings.TrimSpace(item.WorkerID) != workerID {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(item.ToolName))
		current, exists := out[name]
		if !exists || item.ObservedAt.After(current.ObservedAt) {
			out[name] = item
		}
	}
	return out
}
