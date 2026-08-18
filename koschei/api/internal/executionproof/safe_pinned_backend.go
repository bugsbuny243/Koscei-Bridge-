package executionproof

import (
	"context"
	"fmt"
	"strings"

	"koschei/api/internal/matrixcontainment"
)

// SafeSimulationEngine is the narrow trusted adapter implemented by a concrete
// isolated EVM runtime. It must execute the exact Safe transaction against the
// requested pinned state and return observed state/effect evidence only.
type SafeSimulationEngine interface {
	PinnedBlock(ctx context.Context, chainID, blockNumber uint64) (string, error)
	RunnerSHA256(ctx context.Context) (string, error)
	SnapshotSafe(ctx context.Context, chainID, blockNumber uint64, safe string) (SafeAuthoritySnapshot, string, error)
	ExecuteExactSafe(ctx context.Context, input matrixcontainment.CellInput, tx SafeTransaction) (SafeSimulationResult, error)
}

type SafeSimulationResult struct {
	PostAuthority   SafeAuthoritySnapshot
	PostStateSHA256 string
	EffectSetSHA256 string
	AssetMovements []SafeAssetMovement
	Trace           SafeTraceEvidence
}

type PinnedSafeBackend struct {
	Engine SafeSimulationEngine
}

func (b PinnedSafeBackend) ExecuteSafe(ctx context.Context, input matrixcontainment.CellInput, tx SafeTransaction) (SafeExecutionEvidence, error) {
	if b.Engine == nil { return SafeExecutionEvidence{}, fmt.Errorf("Safe simulation engine unavailable") }
	if err := ctx.Err(); err != nil { return SafeExecutionEvidence{}, err }
	if tx.ChainID != input.ChainID || !strings.EqualFold(normalizeAddress(tx.To), normalizeAddress(input.Target)) {
		return SafeExecutionEvidence{}, fmt.Errorf("Safe transaction/input mismatch")
	}

	pinnedHash, err := b.Engine.PinnedBlock(ctx, input.ChainID, input.BlockNumber)
	if err != nil { return SafeExecutionEvidence{}, fmt.Errorf("resolve pinned block: %w", err) }
	if !equalHex32(pinnedHash, input.BlockHash) { return SafeExecutionEvidence{}, fmt.Errorf("pinned block identity mismatch") }

	runnerSHA, err := b.Engine.RunnerSHA256(ctx)
	if err != nil { return SafeExecutionEvidence{}, fmt.Errorf("resolve runner identity: %w", err) }
	if !validSHA256Text(runnerSHA) || !strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(runnerSHA), "0x"), strings.TrimPrefix(strings.TrimSpace(input.ApprovedRunnerSHA256), "0x")) {
		return SafeExecutionEvidence{}, fmt.Errorf("runner identity mismatch")
	}

	before, preStateSHA, err := b.Engine.SnapshotSafe(ctx, input.ChainID, input.BlockNumber, tx.Safe)
	if err != nil { return SafeExecutionEvidence{}, fmt.Errorf("snapshot Safe pre-state: %w", err) }
	if !validAuthoritySnapshot(before) || !validSHA256Text(preStateSHA) { return SafeExecutionEvidence{}, fmt.Errorf("invalid Safe pre-state evidence") }

	result, err := b.Engine.ExecuteExactSafe(ctx, input, tx)
	if err != nil { return SafeExecutionEvidence{}, fmt.Errorf("execute exact Safe action: %w", err) }
	if err := ctx.Err(); err != nil { return SafeExecutionEvidence{}, err }
	if !validAuthoritySnapshot(result.PostAuthority) || !validSHA256Text(result.PostStateSHA256) || !validSHA256Text(result.EffectSetSHA256) {
		return SafeExecutionEvidence{}, fmt.Errorf("invalid Safe post-state evidence")
	}
	for _, movement := range result.AssetMovements {
		if !validAssetMovement(movement) { return SafeExecutionEvidence{}, fmt.Errorf("invalid Safe asset movement evidence") }
	}
	if !(SafeTraceVerifier{}).Verify(result.Trace) || normalizeAddress(result.Trace.RootSafe) != normalizeAddress(tx.Safe) {
		return SafeExecutionEvidence{}, fmt.Errorf("invalid Safe execution trace evidence")
	}

	return SafeExecutionEvidence{
		ChainID: input.ChainID, BlockNumber: input.BlockNumber, BlockHash: strings.TrimSpace(pinnedHash),
		RunnerSHA256: strings.TrimPrefix(strings.TrimSpace(runnerSHA), "0x"),
		PreStateSHA256: strings.TrimPrefix(strings.TrimSpace(preStateSHA), "0x"),
		PostStateSHA256: strings.TrimPrefix(strings.TrimSpace(result.PostStateSHA256), "0x"),
		EffectSetSHA256: strings.TrimPrefix(strings.TrimSpace(result.EffectSetSHA256), "0x"),
		Before: before, After: result.PostAuthority,
		AssetMovements: append([]SafeAssetMovement(nil), result.AssetMovements...),
		Trace: result.Trace,
	}, nil
}
