package executionproof

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"koschei/api/internal/executioncontainment"
)

const SafeAnvilInertTargetEngineVersionV05 = "koschei-safe-anvil-inert-target-engine/v0.5"

// AnvilSafeInertTargetEngineV05 narrows v0.4 materialization to a code-less,
// non-Safe recipient proven at the exact pinned source block. This makes the
// single native movement representation complete for the validated subset:
// the recipient cannot execute receive/fallback code or forward value.
type AnvilSafeInertTargetEngineV05 struct {
	AnvilSafeSimulationEngine
}

func (e AnvilSafeInertTargetEngineV05) ExecuteExactSafe(ctx context.Context, input executioncontainment.CellInput, tx SafeTransaction) (SafeSimulationResult, error) {
	if normalizeAddress(tx.To) == normalizeAddress(tx.Safe) {
		return SafeSimulationResult{}, errors.New("validated inert-target subset rejects Safe self-transfer")
	}
	client, err := e.upstreamClientV04()
	if err != nil {
		return SafeSimulationResult{}, err
	}
	code, err := client.codeAtV04(ctx, tx.To, fmt.Sprintf("0x%x", input.BlockNumber))
	if err != nil {
		return SafeSimulationResult{}, fmt.Errorf("verify inert target code: %w", err)
	}
	if strings.TrimSpace(strings.ToLower(code)) != "0x" {
		return SafeSimulationResult{}, errors.New("validated inert-target subset requires code-less recipient at pinned block")
	}
	result, err := e.AnvilSafeSimulationEngine.ExecuteExactSafe(ctx, input, tx)
	if err != nil {
		return SafeSimulationResult{}, err
	}
	if len(result.AssetMovements) > 1 {
		return SafeSimulationResult{}, errors.New("validated inert-target subset observed unexpected movement fan-out")
	}
	return result, nil
}
