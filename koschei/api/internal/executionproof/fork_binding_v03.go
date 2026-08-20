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

type PreparedVerifiedForkRequest struct {
	Simulation ForkSimulationRequest
	Payload    EVMPayload
	Invariants []ApprovedInvariantDefinition
}

type VerifiedForkBackendResult struct {
	ObservedRunnerSHA256 string                `json:"observed_runner_sha256"`
	Simulation           ForkBackendResult     `json:"simulation"`
	Execution            ForkExecutionEvidence `json:"execution"`
}

type VerifiedForkBackend interface {
	ExecuteVerifiedFork(ctx context.Context, request PreparedVerifiedForkRequest) (VerifiedForkBackendResult, error)
}

type verifiedForkAdapter struct{ result ForkBackendResult }

func (a verifiedForkAdapter) ExecuteForkSimulation(context.Context, ForkSimulationRequest) (ForkBackendResult, error) {
	return a.result, nil
}

func RunVerifiedForkInvariants(ctx context.Context, request VerifiedForkRequest, backend VerifiedForkBackend) (ForkSimulationReceipt, error) {
	_, _, receipt, err := runVerifiedForkCore(ctx, request, backend)
	return receipt, err
}

func RunVerifiedForkExecution(ctx context.Context, request VerifiedForkRequest, backend VerifiedForkBackend) (VerifiedForkReceipt, error) {
	_, result, simulation, err := runVerifiedForkCore(ctx, request, backend)
	if err != nil {
		return blockedVerifiedForkReceipt(simulation, result.Execution), err
	}
	if !validForkExecutionEvidence(result.Execution, simulation.Checks) {
		return blockedVerifiedForkReceipt(simulation, result.Execution), ErrSimulationBlocked
	}

	receipt := VerifiedForkReceipt{
		Version:    VerifiedForkReceiptVersion,
		Simulation: simulation,
		Execution: ForkExecutionEvidence{
			ExecutionModel:           strings.TrimSpace(result.Execution.ExecutionModel),
			TransactionHash:          normalizeHex32(result.Execution.TransactionHash),
			TransactionReceiptSHA256: strings.ToLower(strings.TrimSpace(result.Execution.TransactionReceiptSHA256)),
			InvariantEvidenceSHA256:  strings.ToLower(strings.TrimSpace(result.Execution.InvariantEvidenceSHA256)),
		},
	}
	receipt.ReceiptSHA256 = verifiedForkReceiptDigest(receipt)
	if !ValidVerifiedForkReceipt(receipt) {
		return blockedVerifiedForkReceipt(simulation, result.Execution), ErrSimulationBlocked
	}
	return receipt, nil
}

func blockedVerifiedForkReceipt(simulation ForkSimulationReceipt, execution ForkExecutionEvidence) VerifiedForkReceipt {
	if simulation.Decision == "" {
		simulation.Decision = SimulationBlock
	}
	return VerifiedForkReceipt{
		Version:    VerifiedForkReceiptVersion,
		Simulation: simulation,
		Execution:  execution,
	}
}

func runVerifiedForkCore(ctx context.Context, request VerifiedForkRequest, backend VerifiedForkBackend) (PreparedVerifiedForkRequest, VerifiedForkBackendResult, ForkSimulationReceipt, error) {
	prepared, ok := prepareVerifiedForkRequest(request)
	if !ok || backend == nil {
		receipt := blockedSimulationReceipt(prepared.Simulation, nil, SimulationInvalidRequest)
		return prepared, VerifiedForkBackendResult{}, receipt, ErrSimulationBlocked
	}
	if err := ctx.Err(); err != nil {
		receipt := blockedSimulationReceipt(prepared.Simulation, nil, SimulationBackendFailure)
		return prepared, VerifiedForkBackendResult{}, receipt, err
	}

	result, err := backend.ExecuteVerifiedFork(ctx, prepared)
	if err != nil {
		receipt := blockedSimulationReceipt(prepared.Simulation, nil, SimulationBackendFailure)
		return prepared, result, receipt, err
	}
	if !equalDigest(result.ObservedRunnerSHA256, prepared.Simulation.RunnerSHA256) {
		receipt := blockedSimulationReceipt(prepared.Simulation, result.Simulation.Checks, SimulationRunnerMismatch)
		return prepared, result, receipt, ErrSimulationBlocked
	}
	if !equalDigest(result.Simulation.ObservedInvariantSetHash, prepared.Simulation.InvariantSetSHA256) {
		receipt := blockedSimulationReceipt(prepared.Simulation, result.Simulation.Checks, SimulationInvariantDefinitionMismatch)
		return prepared, result, receipt, ErrSimulationBlocked
	}

	receipt, err := RunForkInvariants(ctx, prepared.Simulation, verifiedForkAdapter{result: result.Simulation})
	return prepared, result, receipt, err
}

func prepareVerifiedForkRequest(request VerifiedForkRequest) (PreparedVerifiedForkRequest, bool) {
	if request.Version == "" {
		request.Version = ExecutionProofForkBindingVersion
	}
	payload, validPayload := canonicalEVMPayload(request.Payload)
	payloadSHA256, validPayloadDigest := evmPayloadDigest(payload)
	if request.Version != ExecutionProofForkBindingVersion || request.ChainID == 0 || request.ReferenceBlock == 0 || !validHex32(request.ReferenceBlockHash) || !validPayload || !validPayloadDigest || !validSHA256(request.RunnerSHA256) {
		return PreparedVerifiedForkRequest{}, false
	}

	invariants, ok := canonicalizeApprovedInvariantDefinitions(request.Invariants)
	if !ok {
		return PreparedVerifiedForkRequest{}, false
	}
	ids := make([]string, 0, len(invariants))
	for _, invariant := range invariants {
		ids = append(ids, invariant.ID)
	}

	return PreparedVerifiedForkRequest{
		Simulation: ForkSimulationRequest{
			Version:            InvariantRunnerVersion,
			ChainID:            request.ChainID,
			ReferenceBlock:     request.ReferenceBlock,
			ReferenceBlockHash: normalizeHex32(request.ReferenceBlockHash),
			PayloadSHA256:      payloadSHA256,
			InvariantSetSHA256: approvedInvariantSetDigest(invariants),
			RunnerSHA256:       strings.ToLower(request.RunnerSHA256),
			RequiredCheckIDs:   ids,
		},
		Payload:    payload,
		Invariants: append([]ApprovedInvariantDefinition(nil), invariants...),
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
