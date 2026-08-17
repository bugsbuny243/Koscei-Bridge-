package executionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const Version = "koschei-execution-proof/v0.1"

type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionBlock Decision = "BLOCK"
)

type ReasonCode string

const (
	ReasonInvalidEvidence          ReasonCode = "EP-001-INVALID-EVIDENCE"
	ReasonArtifactMismatch        ReasonCode = "EP-002-ARTIFACT-MISMATCH"
	ReasonRuntimeArtifactMismatch ReasonCode = "EP-003-RUNTIME-ARTIFACT-MISMATCH"
	ReasonPayloadMismatch         ReasonCode = "EP-004-PAYLOAD-MISMATCH"
	ReasonInvariantFailed         ReasonCode = "EP-005-INVARIANT-NOT-PASS"
)

type SourceEvidence struct {
	CommitID string `json:"commit_id"`
	TreeID   string `json:"tree_id"`
}

type BuildEvidence struct {
	ToolchainSHA256        string `json:"toolchain_sha256"`
	ApprovedArtifactSHA256 string `json:"approved_artifact_sha256"`
	BuiltArtifactSHA256    string `json:"built_artifact_sha256"`
}

type RuntimeEvidence struct {
	ObservedArtifactSHA256 string `json:"observed_artifact_sha256"`
	PolicySHA256           string `json:"policy_sha256"`
	NodeShieldAttestation  string `json:"nodeshield_attestation,omitempty"`
}

type PayloadEvidence struct {
	ChainID                 uint64 `json:"chain_id"`
	Target                  string `json:"target"`
	ApprovedCalldataSHA256  string `json:"approved_calldata_sha256"`
	GeneratedCalldataSHA256 string `json:"generated_calldata_sha256"`
	GeneratorSHA256         string `json:"generator_sha256"`
}

type SimulationEvidence struct {
	InvariantSetSHA256 string `json:"invariant_set_sha256"`
	Result             string `json:"result"`
}

type AuthorizationEvidence struct {
	SigningPolicySHA256      string `json:"signing_policy_sha256"`
	ApprovedSigningRequestID string `json:"approved_signing_request_id"`
}

type Envelope struct {
	Version       string                `json:"version"`
	Source        SourceEvidence        `json:"source"`
	Build         BuildEvidence         `json:"build"`
	Runtime       RuntimeEvidence       `json:"runtime"`
	Payload       PayloadEvidence       `json:"payload"`
	Simulation    SimulationEvidence    `json:"simulation"`
	Authorization AuthorizationEvidence `json:"authorization"`
}

type Evaluation struct {
	Decision Decision     `json:"decision"`
	Reasons  []ReasonCode `json:"reasons"`
}

type Proof struct {
	Envelope       Envelope   `json:"envelope"`
	Evaluation     Evaluation `json:"evaluation"`
	EnvelopeSHA256 string     `json:"envelope_sha256"`
}

func Evaluate(envelope Envelope) (Proof, error) {
	if envelope.Version == "" {
		envelope.Version = Version
	}

	reasons := make([]ReasonCode, 0, 5)
	if envelope.Version != Version || !validEvidence(envelope) {
		reasons = append(reasons, ReasonInvalidEvidence)
	}
	if validSHA256(envelope.Build.ApprovedArtifactSHA256) && validSHA256(envelope.Build.BuiltArtifactSHA256) && !equalDigest(envelope.Build.ApprovedArtifactSHA256, envelope.Build.BuiltArtifactSHA256) {
		reasons = append(reasons, ReasonArtifactMismatch)
	}
	if validSHA256(envelope.Build.ApprovedArtifactSHA256) && validSHA256(envelope.Runtime.ObservedArtifactSHA256) && !equalDigest(envelope.Build.ApprovedArtifactSHA256, envelope.Runtime.ObservedArtifactSHA256) {
		reasons = append(reasons, ReasonRuntimeArtifactMismatch)
	}
	if validSHA256(envelope.Payload.ApprovedCalldataSHA256) && validSHA256(envelope.Payload.GeneratedCalldataSHA256) && !equalDigest(envelope.Payload.ApprovedCalldataSHA256, envelope.Payload.GeneratedCalldataSHA256) {
		reasons = append(reasons, ReasonPayloadMismatch)
	}
	if envelope.Simulation.Result != "PASS" {
		reasons = append(reasons, ReasonInvariantFailed)
	}

	decision := DecisionAllow
	if len(reasons) != 0 {
		decision = DecisionBlock
	}

	canonical, err := json.Marshal(envelope)
	if err != nil {
		return Proof{}, fmt.Errorf("marshal canonical envelope: %w", err)
	}
	digest := sha256.Sum256(canonical)

	return Proof{
		Envelope:       envelope,
		Evaluation:     Evaluation{Decision: decision, Reasons: reasons},
		EnvelopeSHA256: hex.EncodeToString(digest[:]),
	}, nil
}

func CanonicalBytes(proof Proof) ([]byte, error) {
	return json.Marshal(proof)
}

func validEvidence(e Envelope) bool {
	return validGitObjectID(e.Source.CommitID) &&
		validGitObjectID(e.Source.TreeID) &&
		validSHA256(e.Build.ToolchainSHA256) &&
		validSHA256(e.Build.ApprovedArtifactSHA256) &&
		validSHA256(e.Build.BuiltArtifactSHA256) &&
		validSHA256(e.Runtime.ObservedArtifactSHA256) &&
		validSHA256(e.Runtime.PolicySHA256) &&
		e.Payload.ChainID != 0 &&
		strings.TrimSpace(e.Payload.Target) != "" &&
		validSHA256(e.Payload.ApprovedCalldataSHA256) &&
		validSHA256(e.Payload.GeneratedCalldataSHA256) &&
		validSHA256(e.Payload.GeneratorSHA256) &&
		validSHA256(e.Simulation.InvariantSetSHA256) &&
		validSHA256(e.Authorization.SigningPolicySHA256) &&
		validHex32(e.Authorization.ApprovedSigningRequestID)
}

func validGitObjectID(v string) bool {
	if len(v) != 40 && len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func validSHA256(v string) bool {
	if len(v) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func validHex32(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "0x")
	return validSHA256(v)
}

func equalDigest(a, b string) bool {
	return strings.EqualFold(a, b)
}
