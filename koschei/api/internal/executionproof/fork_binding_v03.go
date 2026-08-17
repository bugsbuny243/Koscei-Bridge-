package executionproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

const ExecutionProofForkBindingVersion = "koschei-fork-binding/v0.3"

const (
	SimulationInvariantDefinitionMismatch SimulationReason = "SIM-011-INVARIANT-DEFINITION-MISMATCH"
	SimulationRunnerMismatch              SimulationReason = "SIM-012-RUNNER-MISMATCH"
)

type ApprovedInvariantDefinition struct {
	ID               string         `json:"id"`
	Class            InvariantClass `json:"class"`
	ParametersSHA256 string         `json:"parameters_sha256"`
}

type VerifiedForkRequest struct {
	Version            string                        `json:"version"`
	ChainID            uint64                        `json:"chain_id"`
	ReferenceBlock     uint64                        `json:"reference_block"`
	ReferenceBlockHash string                        `json:"reference_block_hash"`
	Payload            EVMPayload                    `json:"payload"`
	RunnerSHA256       string                        `json:"runner_sha256"`
	Invariants         []ApprovedInvariantDefinition `json:"invariants"`
}

type VerifiedForkBackendResult struct {
	ObservedRunnerSHA256 string            `json:"observed_runner_sha256"`
	Simulation           ForkBackendResult `json:"simulation"`
}

type VerifiedForkBackend interface {
	ExecuteVerifiedFork(ctx context.Context, request ForkSimulationRequest) (VerifiedForkBackendResult, error)
}

type verifiedForkAdapter struct {
	result ForkBackendResult
}

func (a verifiedForkAdapter) ExecuteForkSimulation(context.Context, ForkSimulationRequest) (ForkBackendResult, error) {
	return a.result, nil
}

func RunVerifiedForkInvariants(ctx context.Context, request VerifiedForkRequest, backend VerifiedForkBackend) (ForkSimulationReceipt, error) {
	prepared, ok := prepareVerifiedForkRequest(request)
	if !ok || backend == nil {
		return blockedSimulationReceipt(prepared, nil, SimulationInvalidRequest), ErrSimulationBlocked
	}
	if err := ctx.Err(); err != nil {
		return blockedSimulationReceipt(prepared, nil, SimulationBackendFailure), err
	}

	result, err := backend.ExecuteVerifiedFork(ctx, prepared)
	if err != nil {
		return blockedSimulationReceipt(prepared, nil, SimulationBackendFailure), err
	}
	if !equalDigest(result.ObservedRunnerSHA256, prepared.RunnerSHA256) {
		return blockedSimulationReceipt(prepared, result.Simulation.Checks, SimulationRunnerMismatch), ErrSimulationBlocked
	}
	if !equalDigest(result.Simulation.ObservedInvariantSetHash, prepared.InvariantSetSHA256) {
		return blockedSimulationReceipt(prepared, result.Simulation.Checks, SimulationInvariantDefinitionMismatch), ErrSimulationBlocked
	}

	return RunForkInvariants(ctx, prepared, verifiedForkAdapter{result: result.Simulation})
}

func prepareVerifiedForkRequest(request VerifiedForkRequest) (ForkSimulationRequest, bool) {
	if request.Version == "" {
		request.Version = ExecutionProofForkBindingVersion
	}
	payloadSHA256, validPayload := evmPayloadDigest(request.Payload)
	if request.Version != ExecutionProofForkBindingVersion || request.ChainID == 0 || request.ReferenceBlock == 0 || !validHex32(request.ReferenceBlockHash) || !validPayload || !validSHA256(request.RunnerSHA256) {
		return ForkSimulationRequest{}, false
	}

	invariants, ok := canonicalizeApprovedInvariantDefinitions(request.Invariants)
	if !ok {
		return ForkSimulationRequest{}, false
	}
	ids := make([]string, 0, len(invariants))
	for _, invariant := range invariants {
		ids = append(ids, invariant.ID)
	}

	return ForkSimulationRequest{
		Version:            InvariantRunnerVersion,
		ChainID:            request.ChainID,
		ReferenceBlock:     request.ReferenceBlock,
		ReferenceBlockHash: normalizeHex32(request.ReferenceBlockHash),
		PayloadSHA256:      payloadSHA256,
		InvariantSetSHA256: approvedInvariantSetDigest(invariants),
		RunnerSHA256:       strings.ToLower(request.RunnerSHA256),
		RequiredCheckIDs:   ids,
	}, true
}

func canonicalizeApprovedInvariantDefinitions(input []ApprovedInvariantDefinition) ([]ApprovedInvariantDefinition, bool) {
	if len(input) == 0 {
		return nil, false
	}
	invariants := append([]ApprovedInvariantDefinition(nil), input...)
	seen := make(map[string]struct{}, len(invariants))
	for i := range invariants {
		invariants[i].ID = strings.TrimSpace(invariants[i].ID)
		invariants[i].ParametersSHA256 = strings.ToLower(strings.TrimSpace(invariants[i].ParametersSHA256))
		if invariants[i].ID == "" || !validInvariantClass(invariants[i].Class) || !validSHA256(invariants[i].ParametersSHA256) {
			return nil, false
		}
		if _, exists := seen[invariants[i].ID]; exists {
			return nil, false
		}
		seen[invariants[i].ID] = struct{}{}
	}
	sort.Slice(invariants, func(i, j int) bool { return invariants[i].ID < invariants[j].ID })
	return invariants, true
}

func approvedInvariantSetDigest(invariants []ApprovedInvariantDefinition) string {
	canonical, err := json.Marshal(invariants)
	if err != nil {
		panic("ApprovedInvariantDefinition must remain JSON serializable")
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

var errVerifiedForkBackend = errors.New("verified fork backend failure")
