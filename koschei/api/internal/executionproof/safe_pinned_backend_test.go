package executionproof

import (
	"context"
	"errors"
	"testing"

	"koschei/api/internal/matrixcontainment"
)

type stubSafeSimulationEngine struct {
	blockHash string
	runnerSHA string
	before    SafeAuthoritySnapshot
	preSHA    string
	result    SafeSimulationResult
	err       error
}

func (s stubSafeSimulationEngine) PinnedBlock(context.Context, uint64, uint64) (string, error) {
	if s.err != nil { return "", s.err }
	return s.blockHash, nil
}
func (s stubSafeSimulationEngine) RunnerSHA256(context.Context) (string, error) {
	if s.err != nil { return "", s.err }
	return s.runnerSHA, nil
}
func (s stubSafeSimulationEngine) SnapshotSafe(context.Context, uint64, uint64, string) (SafeAuthoritySnapshot, string, error) {
	if s.err != nil { return SafeAuthoritySnapshot{}, "", s.err }
	return s.before, s.preSHA, nil
}
func (s stubSafeSimulationEngine) ExecuteExactSafe(context.Context, matrixcontainment.CellInput, SafeTransaction) (SafeSimulationResult, error) {
	if s.err != nil { return SafeSimulationResult{}, s.err }
	return s.result, nil
}

func pinnedBackendFixture(t *testing.T) (matrixcontainment.CellInput, SafeTransaction, stubSafeSimulationEngine) {
	t.Helper()
	input, _, _, evidence := safeRunnerFixture(t)
	tx := validSafeForwardRequest().Transaction
	engine := stubSafeSimulationEngine{
		blockHash: "0x" + input.BlockHash,
		runnerSHA: input.ApprovedRunnerSHA256,
		before: evidence.Before,
		preSHA: evidence.PreStateSHA256,
		result: SafeSimulationResult{
			PostAuthority: evidence.After,
			PostStateSHA256: evidence.PostStateSHA256,
			EffectSetSHA256: evidence.EffectSetSHA256,
			CallPathFullyObserved: true,
		},
	}
	return input, tx, engine
}

func TestPinnedSafeBackendProducesEvidenceOnlyForExactPinnedState(t *testing.T) {
	input, tx, engine := pinnedBackendFixture(t)
	got, err := (PinnedSafeBackend{Engine: engine}).ExecuteSafe(context.Background(), input, tx)
	if err != nil { t.Fatal(err) }
	if got.ChainID != input.ChainID || got.BlockNumber != input.BlockNumber {
		t.Fatalf("unexpected identity: %+v", got)
	}
	if !got.CallPathFullyObserved || got.Before.Threshold != got.After.Threshold {
		t.Fatalf("unexpected evidence: %+v", got)
	}
}

func TestPinnedSafeBackendRejectsWrongBlock(t *testing.T) {
	input, tx, engine := pinnedBackendFixture(t)
	engine.blockHash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	_, err := (PinnedSafeBackend{Engine: engine}).ExecuteSafe(context.Background(), input, tx)
	if err == nil { t.Fatal("expected pinned block mismatch") }
}

func TestPinnedSafeBackendRejectsWrongRunner(t *testing.T) {
	input, tx, engine := pinnedBackendFixture(t)
	engine.runnerSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, err := (PinnedSafeBackend{Engine: engine}).ExecuteSafe(context.Background(), input, tx)
	if err == nil { t.Fatal("expected runner mismatch") }
}

func TestPinnedSafeBackendRejectsTargetMutation(t *testing.T) {
	input, tx, engine := pinnedBackendFixture(t)
	tx.To = "0x9999999999999999999999999999999999999999"
	_, err := (PinnedSafeBackend{Engine: engine}).ExecuteSafe(context.Background(), input, tx)
	if err == nil { t.Fatal("expected transaction/input mismatch") }
}

func TestPinnedSafeBackendPropagatesEngineFailure(t *testing.T) {
	input, tx, engine := pinnedBackendFixture(t)
	engine.err = errors.New("isolated runtime failed")
	_, err := (PinnedSafeBackend{Engine: engine}).ExecuteSafe(context.Background(), input, tx)
	if err == nil { t.Fatal("expected engine failure") }
}

func TestPinnedSafeBackendRejectsCancelledContext(t *testing.T) {
	input, tx, engine := pinnedBackendFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (PinnedSafeBackend{Engine: engine}).ExecuteSafe(ctx, input, tx)
	if err == nil { t.Fatal("expected cancellation") }
}
