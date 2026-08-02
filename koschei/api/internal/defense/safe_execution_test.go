package defense

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeToolchainPolicyToolsRequiresExactPinnedSet(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	input := map[string]string{
		"rustc":   hash,
		"cargo":   hash,
		"solana":  hash,
		"anchor":  hash,
		"litesvm": hash,
	}
	got, err := normalizeToolchainPolicyTools(input)
	if err != nil {
		t.Fatalf("normalize policy tools: %v", err)
	}
	if len(got) != 5 || got["litesvm"] != hash {
		t.Fatalf("unexpected normalized tools: %#v", got)
	}

	delete(input, "litesvm")
	input["trident"] = hash
	if _, err := normalizeToolchainPolicyTools(input); err == nil {
		t.Fatal("expected Trident substitution to be rejected in Phase 12")
	}
}

func TestNormalizeToolchainPolicyToolsRejectsUnpinnedHash(t *testing.T) {
	valid := "sha256:" + strings.Repeat("b", 64)
	input := map[string]string{
		"rustc":   valid,
		"cargo":   valid,
		"solana":  valid,
		"anchor":  valid,
		"litesvm": "1.2.3",
	}
	if _, err := normalizeToolchainPolicyTools(input); err == nil {
		t.Fatal("expected plain version string to be rejected")
	}
}

func TestEvaluateToolchainPolicyAuthorizesOnlyExactWorkerAndLatestAttestations(t *testing.T) {
	now := time.Now().UTC()
	image := "sha256:" + strings.Repeat("c", 64)
	policy := ToolchainPolicy{
		PolicyRef:         "KTP1-0123456789abcdef0123456789abcdef",
		WorkerImageDigest: image,
		RequiredTools: map[string]string{
			"anchor":  "sha256:" + strings.Repeat("1", 64),
			"cargo":   "sha256:" + strings.Repeat("2", 64),
			"litesvm": "sha256:" + strings.Repeat("3", 64),
			"rustc":   "sha256:" + strings.Repeat("4", 64),
			"solana":  "sha256:" + strings.Repeat("5", 64),
		},
	}
	attestations := []ToolchainAttestation{
		{AttestationRef: "old-rustc", WorkerID: "worker-1", ToolName: "rustc", Available: false, VersionHash: policy.RequiredTools["rustc"], ObservedAt: now.Add(-time.Hour)},
		{AttestationRef: "rustc", WorkerID: "worker-1", ToolName: "rustc", Available: true, VersionHash: policy.RequiredTools["rustc"], ObservedAt: now},
		{AttestationRef: "cargo", WorkerID: "worker-1", ToolName: "cargo", Available: true, VersionHash: policy.RequiredTools["cargo"], ObservedAt: now},
		{AttestationRef: "solana", WorkerID: "worker-1", ToolName: "solana", Available: true, VersionHash: policy.RequiredTools["solana"], ObservedAt: now},
		{AttestationRef: "anchor", WorkerID: "worker-1", ToolName: "anchor", Available: true, VersionHash: policy.RequiredTools["anchor"], ObservedAt: now},
		{AttestationRef: "litesvm", WorkerID: "worker-1", ToolName: "litesvm", Available: true, VersionHash: policy.RequiredTools["litesvm"], ObservedAt: now},
	}

	result := EvaluateToolchainPolicy(policy, "worker-1", image, attestations)
	if !result.ExecutionAuthorized || result.Status != "pinned_toolchain_verified" {
		t.Fatalf("expected exact policy match, got %#v", result)
	}
	if result.VerdictAuthority {
		t.Fatal("toolchain policy must never have verdict authority")
	}
	if len(result.MatchedTools) != 5 || len(result.EvidenceRefs) != 5 {
		t.Fatalf("expected five matched evidence rows, got %#v", result)
	}
}

func TestEvaluateToolchainPolicyFailsClosedOnImageMissingOrMismatch(t *testing.T) {
	now := time.Now().UTC()
	image := "sha256:" + strings.Repeat("d", 64)
	hash := "sha256:" + strings.Repeat("e", 64)
	policy := ToolchainPolicy{
		PolicyRef:         "KTP1-fedcba9876543210fedcba9876543210",
		WorkerImageDigest: image,
		RequiredTools: map[string]string{
			"anchor":  hash,
			"cargo":   hash,
			"litesvm": hash,
			"rustc":   hash,
			"solana":  hash,
		},
	}
	attestations := []ToolchainAttestation{
		{WorkerID: "worker-1", ToolName: "rustc", Available: true, VersionHash: hash, ObservedAt: now},
		{WorkerID: "worker-1", ToolName: "cargo", Available: true, VersionHash: hash, ObservedAt: now},
		{WorkerID: "worker-1", ToolName: "solana", Available: true, VersionHash: hash, ObservedAt: now},
		{WorkerID: "worker-1", ToolName: "anchor", Available: true, VersionHash: hash, ObservedAt: now},
	}

	result := EvaluateToolchainPolicy(policy, "worker-1", "sha256:"+strings.Repeat("f", 64), attestations)
	if result.ExecutionAuthorized {
		t.Fatal("image mismatch and missing LiteSVM must fail closed")
	}
	if result.Status != "toolchain_mismatch" || len(result.MissingTools) != 1 || result.MissingTools[0] != "litesvm" {
		t.Fatalf("unexpected fail-closed result: %#v", result)
	}
}

func TestEvaluateToolchainPolicyUsesLatestAttestation(t *testing.T) {
	now := time.Now().UTC()
	image := "sha256:" + strings.Repeat("0", 64)
	hash := "sha256:" + strings.Repeat("1", 64)
	policy := ToolchainPolicy{
		WorkerImageDigest: image,
		RequiredTools: map[string]string{
			"anchor":  hash,
			"cargo":   hash,
			"litesvm": hash,
			"rustc":   hash,
			"solana":  hash,
		},
	}
	attestations := []ToolchainAttestation{}
	for _, tool := range phase12RequiredTools {
		attestations = append(attestations, ToolchainAttestation{WorkerID: "worker-1", ToolName: tool, Available: true, VersionHash: hash, ObservedAt: now.Add(-time.Minute)})
	}
	attestations = append(attestations, ToolchainAttestation{WorkerID: "worker-1", ToolName: "cargo", Available: false, VersionHash: hash, ObservedAt: now})

	result := EvaluateToolchainPolicy(policy, "worker-1", image, attestations)
	if result.ExecutionAuthorized {
		t.Fatal("latest unavailable attestation must revoke authorization")
	}
	if len(result.MissingTools) != 1 || result.MissingTools[0] != "cargo" {
		t.Fatalf("unexpected missing tools: %#v", result.MissingTools)
	}
}
