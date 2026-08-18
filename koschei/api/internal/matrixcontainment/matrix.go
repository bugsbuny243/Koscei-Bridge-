package matrixcontainment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const Version = "koschei-matrix-containment/v0.1"

type Decision string

const (
	DecisionRelease     Decision = "RELEASE"
	DecisionContain     Decision = "CONTAIN"
	DecisionUnavailable Decision = "UNAVAILABLE"
)

type ReasonCode string

const (
	ReasonInvalidEvidence       ReasonCode = "MX-001-INVALID-EVIDENCE"
	ReasonBackendUnavailable    ReasonCode = "MX-002-BACKEND-UNAVAILABLE"
	ReasonPinnedStateMismatch   ReasonCode = "MX-003-PINNED-STATE-MISMATCH"
	ReasonIntentMismatch        ReasonCode = "MX-004-INTENT-MISMATCH"
	ReasonAuthorityChanged      ReasonCode = "MX-005-AUTHORITY-CHANGED"
	ReasonAssetBoundsExceeded   ReasonCode = "MX-006-ASSET-BOUNDS-EXCEEDED"
	ReasonCodeIntegrityChanged  ReasonCode = "MX-007-CODE-INTEGRITY-CHANGED"
	ReasonHiddenExecutionPath   ReasonCode = "MX-008-HIDDEN-EXECUTION-PATH"
	ReasonInvariantFailed       ReasonCode = "MX-009-INVARIANT-FAILED"
	ReasonRunnerIdentityMismatch ReasonCode = "MX-010-RUNNER-IDENTITY-MISMATCH"
)

type CellInput struct {
	Version                 string `json:"version"`
	ChainID                 uint64 `json:"chain_id"`
	BlockNumber             uint64 `json:"block_number"`
	BlockHash               string `json:"block_hash"`
	Target                  string `json:"target"`
	ApprovedIntentSHA256    string `json:"approved_intent_sha256"`
	CandidateIntentSHA256   string `json:"candidate_intent_sha256"`
	ApprovedPayloadSHA256   string `json:"approved_payload_sha256"`
	CandidatePayloadSHA256  string `json:"candidate_payload_sha256"`
	InvariantSetSHA256      string `json:"invariant_set_sha256"`
	ApprovedRunnerSHA256    string `json:"approved_runner_sha256"`
}

type Observation struct {
	BackendAvailable          bool   `json:"backend_available"`
	ObservedChainID           uint64 `json:"observed_chain_id"`
	ObservedBlockNumber       uint64 `json:"observed_block_number"`
	ObservedBlockHash         string `json:"observed_block_hash"`
	ObservedRunnerSHA256      string `json:"observed_runner_sha256"`
	PreStateSHA256            string `json:"pre_state_sha256"`
	PostStateSHA256           string `json:"post_state_sha256"`
	EffectSetSHA256           string `json:"effect_set_sha256"`
	AuthorityPreserved        bool   `json:"authority_preserved"`
	AssetBoundsPreserved      bool   `json:"asset_bounds_preserved"`
	CodeIntegrityPreserved    bool   `json:"code_integrity_preserved"`
	ExecutionPathFullyObserved bool  `json:"execution_path_fully_observed"`
	InvariantsPass            bool   `json:"invariants_pass"`
}

type Receipt struct {
	Version       string       `json:"version"`
	Input         CellInput    `json:"input"`
	Observation   Observation  `json:"observation"`
	Decision      Decision     `json:"decision"`
	Reasons       []ReasonCode `json:"reasons"`
	InputSHA256   string       `json:"input_sha256"`
	ReceiptSHA256 string       `json:"receipt_sha256"`
}

func Evaluate(input CellInput, observation Observation) (Receipt, error) {
	if input.Version == "" {
		input.Version = Version
	}

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return Receipt{}, fmt.Errorf("marshal matrix input: %w", err)
	}
	inputDigest := sha256.Sum256(inputBytes)

	reasons := make([]ReasonCode, 0, 10)
	if !validInput(input) || !validObservationShape(observation) {
		reasons = append(reasons, ReasonInvalidEvidence)
	}

	decision := DecisionRelease
	if !observation.BackendAvailable {
		decision = DecisionUnavailable
		reasons = append(reasons, ReasonBackendUnavailable)
	}

	if observation.BackendAvailable {
		if observation.ObservedChainID != input.ChainID ||
			observation.ObservedBlockNumber != input.BlockNumber ||
			!equalDigest(observation.ObservedBlockHash, input.BlockHash) {
			reasons = append(reasons, ReasonPinnedStateMismatch)
		}
		if !equalDigest(observation.ObservedRunnerSHA256, input.ApprovedRunnerSHA256) {
			reasons = append(reasons, ReasonRunnerIdentityMismatch)
		}
	}

	if !equalDigest(input.ApprovedIntentSHA256, input.CandidateIntentSHA256) ||
		!equalDigest(input.ApprovedPayloadSHA256, input.CandidatePayloadSHA256) {
		reasons = append(reasons, ReasonIntentMismatch)
	}
	if !observation.AuthorityPreserved {
		reasons = append(reasons, ReasonAuthorityChanged)
	}
	if !observation.AssetBoundsPreserved {
		reasons = append(reasons, ReasonAssetBoundsExceeded)
	}
	if !observation.CodeIntegrityPreserved {
		reasons = append(reasons, ReasonCodeIntegrityChanged)
	}
	if !observation.ExecutionPathFullyObserved {
		reasons = append(reasons, ReasonHiddenExecutionPath)
	}
	if !observation.InvariantsPass {
		reasons = append(reasons, ReasonInvariantFailed)
	}

	if len(reasons) != 0 && decision != DecisionUnavailable {
		decision = DecisionContain
	}

	withoutDigest := struct {
		Version     string       `json:"version"`
		Input       CellInput    `json:"input"`
		Observation Observation  `json:"observation"`
		Decision    Decision     `json:"decision"`
		Reasons     []ReasonCode `json:"reasons"`
		InputSHA256 string       `json:"input_sha256"`
	}{
		Version:     Version,
		Input:       input,
		Observation: observation,
		Decision:    decision,
		Reasons:     reasons,
		InputSHA256: hex.EncodeToString(inputDigest[:]),
	}

	canonical, err := json.Marshal(withoutDigest)
	if err != nil {
		return Receipt{}, fmt.Errorf("marshal matrix receipt: %w", err)
	}
	receiptDigest := sha256.Sum256(canonical)

	return Receipt{
		Version:       Version,
		Input:         input,
		Observation:   observation,
		Decision:      decision,
		Reasons:       reasons,
		InputSHA256:   hex.EncodeToString(inputDigest[:]),
		ReceiptSHA256: hex.EncodeToString(receiptDigest[:]),
	}, nil
}

func Verify(receipt Receipt) bool {
	if receipt.Version != Version || receipt.InputSHA256 == "" || receipt.ReceiptSHA256 == "" {
		return false
	}
	recomputed, err := Evaluate(receipt.Input, receipt.Observation)
	if err != nil {
		return false
	}
	return recomputed.Decision == receipt.Decision &&
		equalReasonCodes(recomputed.Reasons, receipt.Reasons) &&
		equalDigest(recomputed.InputSHA256, receipt.InputSHA256) &&
		equalDigest(recomputed.ReceiptSHA256, receipt.ReceiptSHA256)
}

func CanonicalBytes(receipt Receipt) ([]byte, error) {
	return json.Marshal(receipt)
}

func validInput(input CellInput) bool {
	return input.Version == Version &&
		input.ChainID != 0 &&
		input.BlockNumber != 0 &&
		strings.TrimSpace(input.Target) != "" &&
		validSHA256(input.BlockHash) &&
		validSHA256(input.ApprovedIntentSHA256) &&
		validSHA256(input.CandidateIntentSHA256) &&
		validSHA256(input.ApprovedPayloadSHA256) &&
		validSHA256(input.CandidatePayloadSHA256) &&
		validSHA256(input.InvariantSetSHA256) &&
		validSHA256(input.ApprovedRunnerSHA256)
}

func validObservationShape(observation Observation) bool {
	if !observation.BackendAvailable {
		return true
	}
	return observation.ObservedChainID != 0 &&
		observation.ObservedBlockNumber != 0 &&
		validSHA256(observation.ObservedBlockHash) &&
		validSHA256(observation.ObservedRunnerSHA256) &&
		validSHA256(observation.PreStateSHA256) &&
		validSHA256(observation.PostStateSHA256) &&
		validSHA256(observation.EffectSetSHA256)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func equalDigest(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func equalReasonCodes(a, b []ReasonCode) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
