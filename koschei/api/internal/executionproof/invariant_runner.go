package executionproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const InvariantRunnerVersion = "koschei-invariant-runner/v0.2"

type InvariantClass string

const (
	InvariantAssetConservation InvariantClass = "ASSET_CONSERVATION"
	InvariantPrivilegedRole    InvariantClass = "PRIVILEGED_ROLE"
	InvariantProxyCodehash     InvariantClass = "PROXY_CODEHASH"
	InvariantTreasuryBound     InvariantClass = "TREASURY_VALUE_BOUND"
	InvariantBridgeReserve     InvariantClass = "BRIDGE_RESERVE_SUPPLY"
)

type ForkSimulationRequest struct {
	Version            string `json:"version"`
	ChainID            uint64 `json:"chain_id"`
	ReferenceBlock     uint64 `json:"reference_block"`
	ReferenceBlockHash string `json:"reference_block_hash"`
	PayloadSHA256      string `json:"payload_sha256"`
	InvariantSetSHA256 string `json:"invariant_set_sha256"`
	RunnerSHA256       string `json:"runner_sha256"`
}

type InvariantCheck struct {
	ID       string         `json:"id"`
	Class    InvariantClass `json:"class"`
	Passed   bool           `json:"passed"`
	Evidence string         `json:"evidence_sha256"`
}

type ForkBackendResult struct {
	ChainID                  uint64           `json:"chain_id"`
	ObservedReferenceBlock   uint64           `json:"observed_reference_block"`
	ObservedReferenceHash    string           `json:"observed_reference_hash"`
	ObservedPayloadSHA256    string           `json:"observed_payload_sha256"`
	ObservedInvariantSetHash string           `json:"observed_invariant_set_sha256"`
	Checks                   []InvariantCheck `json:"checks"`
}

type ForkSimulationBackend interface {
	ExecuteForkSimulation(ctx context.Context, request ForkSimulationRequest) (ForkBackendResult, error)
}

type SimulationDecision string

const (
	SimulationAllow SimulationDecision = "PASS"
	SimulationBlock SimulationDecision = "BLOCK"
)

type SimulationReason string

const (
	SimulationInvalidRequest   SimulationReason = "SIM-001-INVALID-REQUEST"
	SimulationBackendFailure   SimulationReason = "SIM-002-BACKEND-FAILURE"
	SimulationStateMismatch    SimulationReason = "SIM-003-STATE-MISMATCH"
	SimulationPayloadMismatch  SimulationReason = "SIM-004-PAYLOAD-MISMATCH"
	SimulationInvariantDrift   SimulationReason = "SIM-005-INVARIANT-SET-MISMATCH"
	SimulationMissingChecks    SimulationReason = "SIM-006-MISSING-CHECKS"
	SimulationDuplicateCheck   SimulationReason = "SIM-007-DUPLICATE-CHECK"
	SimulationInvariantFailure SimulationReason = "SIM-008-INVARIANT-FAILURE"
	SimulationInvalidEvidence  SimulationReason = "SIM-009-INVALID-EVIDENCE"
)

type ForkSimulationReceipt struct {
	Version            string             `json:"version"`
	ChainID            uint64             `json:"chain_id"`
	ReferenceBlock     uint64             `json:"reference_block"`
	ReferenceBlockHash string             `json:"reference_block_hash"`
	PayloadSHA256      string             `json:"payload_sha256"`
	InvariantSetSHA256 string             `json:"invariant_set_sha256"`
	RunnerSHA256       string             `json:"runner_sha256"`
	Checks             []InvariantCheck   `json:"checks"`
	Decision           SimulationDecision `json:"decision"`
	Reasons            []SimulationReason `json:"reasons"`
	ReceiptSHA256      string             `json:"receipt_sha256"`
}

var ErrSimulationBlocked = errors.New("execution proof invariant simulation blocked")

func RunForkInvariants(ctx context.Context, request ForkSimulationRequest, backend ForkSimulationBackend) (ForkSimulationReceipt, error) {
	if request.Version == "" {
		request.Version = InvariantRunnerVersion
	}
	if !validForkSimulationRequest(request) || backend == nil {
		return blockedSimulationReceipt(request, nil, SimulationInvalidRequest), ErrSimulationBlocked
	}
	if err := ctx.Err(); err != nil {
		return blockedSimulationReceipt(request, nil, SimulationBackendFailure), err
	}

	result, err := backend.ExecuteForkSimulation(ctx, request)
	if err != nil {
		return blockedSimulationReceipt(request, nil, SimulationBackendFailure), fmt.Errorf("fork simulation backend: %w", err)
	}

	reasons := make([]SimulationReason, 0, 4)
	if result.ChainID != request.ChainID || result.ObservedReferenceBlock != request.ReferenceBlock || !equalHex32(result.ObservedReferenceHash, request.ReferenceBlockHash) {
		reasons = append(reasons, SimulationStateMismatch)
	}
	if !equalDigest(result.ObservedPayloadSHA256, request.PayloadSHA256) {
		reasons = append(reasons, SimulationPayloadMismatch)
	}
	if !equalDigest(result.ObservedInvariantSetHash, request.InvariantSetSHA256) {
		reasons = append(reasons, SimulationInvariantDrift)
	}

	checks, checkReasons := canonicalizeInvariantChecks(result.Checks)
	reasons = append(reasons, checkReasons...)

	decision := SimulationAllow
	if len(reasons) != 0 {
		decision = SimulationBlock
	}

	receipt := ForkSimulationReceipt{
		Version:            request.Version,
		ChainID:            request.ChainID,
		ReferenceBlock:     request.ReferenceBlock,
		ReferenceBlockHash: normalizeHex32(request.ReferenceBlockHash),
		PayloadSHA256:      strings.ToLower(request.PayloadSHA256),
		InvariantSetSHA256: strings.ToLower(request.InvariantSetSHA256),
		RunnerSHA256:       strings.ToLower(request.RunnerSHA256),
		Checks:             checks,
		Decision:           decision,
		Reasons:            reasons,
	}
	receipt.ReceiptSHA256 = simulationReceiptDigest(receipt)
	if decision != SimulationAllow {
		return receipt, ErrSimulationBlocked
	}
	return receipt, nil
}

func validForkSimulationRequest(request ForkSimulationRequest) bool {
	return request.Version == InvariantRunnerVersion &&
		request.ChainID != 0 &&
		request.ReferenceBlock != 0 &&
		validHex32(request.ReferenceBlockHash) &&
		validSHA256(request.PayloadSHA256) &&
		validSHA256(request.InvariantSetSHA256) &&
		validSHA256(request.RunnerSHA256)
}

func canonicalizeInvariantChecks(input []InvariantCheck) ([]InvariantCheck, []SimulationReason) {
	if len(input) == 0 {
		return nil, []SimulationReason{SimulationMissingChecks}
	}
	checks := append([]InvariantCheck(nil), input...)
	for i := range checks {
		checks[i].ID = strings.TrimSpace(checks[i].ID)
		checks[i].Evidence = strings.ToLower(strings.TrimSpace(checks[i].Evidence))
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })

	reasons := make([]SimulationReason, 0, 2)
	seen := make(map[string]struct{}, len(checks))
	for i := range checks {
		if checks[i].ID == "" || !validInvariantClass(checks[i].Class) || !validSHA256(checks[i].Evidence) {
			reasons = appendUniqueSimulationReason(reasons, SimulationInvalidEvidence)
		}
		if _, ok := seen[checks[i].ID]; ok {
			reasons = appendUniqueSimulationReason(reasons, SimulationDuplicateCheck)
		}
		seen[checks[i].ID] = struct{}{}
		if !checks[i].Passed {
			reasons = appendUniqueSimulationReason(reasons, SimulationInvariantFailure)
		}
	}
	return checks, reasons
}

func validInvariantClass(class InvariantClass) bool {
	switch class {
	case InvariantAssetConservation, InvariantPrivilegedRole, InvariantProxyCodehash, InvariantTreasuryBound, InvariantBridgeReserve:
		return true
	default:
		return false
	}
}

func appendUniqueSimulationReason(reasons []SimulationReason, reason SimulationReason) []SimulationReason {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func blockedSimulationReceipt(request ForkSimulationRequest, checks []InvariantCheck, reason SimulationReason) ForkSimulationReceipt {
	if request.Version == "" {
		request.Version = InvariantRunnerVersion
	}
	receipt := ForkSimulationReceipt{
		Version:            request.Version,
		ChainID:            request.ChainID,
		ReferenceBlock:     request.ReferenceBlock,
		ReferenceBlockHash: normalizeHex32(request.ReferenceBlockHash),
		PayloadSHA256:      strings.ToLower(strings.TrimSpace(request.PayloadSHA256)),
		InvariantSetSHA256: strings.ToLower(strings.TrimSpace(request.InvariantSetSHA256)),
		RunnerSHA256:       strings.ToLower(strings.TrimSpace(request.RunnerSHA256)),
		Checks:             checks,
		Decision:           SimulationBlock,
		Reasons:            []SimulationReason{reason},
	}
	receipt.ReceiptSHA256 = simulationReceiptDigest(receipt)
	return receipt
}

func simulationReceiptDigest(receipt ForkSimulationReceipt) string {
	copyReceipt := receipt
	copyReceipt.ReceiptSHA256 = ""
	canonical, err := json.Marshal(copyReceipt)
	if err != nil {
		panic("ForkSimulationReceipt must remain JSON serializable")
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

func normalizeHex32(value string) string {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if len(value) != 64 {
		return strings.ToLower(strings.TrimSpace(value))
	}
	return "0x" + strings.ToLower(value)
}
