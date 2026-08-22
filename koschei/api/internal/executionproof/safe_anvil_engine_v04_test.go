package executionproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/executioncontainment"
)

func TestSafeAccessorEncodingV04MatchesExistingSemanticDigest(t *testing.T) {
	tx := SafeTransaction{
		ChainID:   31337,
		Safe:      "0x1111111111111111111111111111111111111111",
		To:        "0x2222222222222222222222222222222222222222",
		Value:     big.NewInt(12345),
		Data:      []byte{0xaa, 0xbb},
		Operation: 0,
		SafeTxGas: big.NewInt(0), BaseGas: big.NewInt(0), GasPrice: big.NewInt(0),
		GasToken:       "0x0000000000000000000000000000000000000000",
		RefundReceiver: "0x0000000000000000000000000000000000000000",
		Nonce:          big.NewInt(1),
	}
	calldata, err := encodeSafeAccessorSimulateV04(tx)
	if err != nil {
		t.Fatal(err)
	}
	got := sha256HexV04(calldata)
	want, ok := safeAccessorSimulateCalldataSHA256(tx)
	if !ok {
		t.Fatal("existing Safe accessor digest rejected valid transaction")
	}
	if got != want {
		t.Fatalf("calldata digest=%s want=%s", got, want)
	}
}

func TestFindSafeAccessorFrameV04BuildsVerifiableTrace(t *testing.T) {
	safe := "0x1111111111111111111111111111111111111111"
	accessor := "0x2222222222222222222222222222222222222222"
	target := "0x3333333333333333333333333333333333333333"
	tx := SafeTransaction{
		ChainID: 1, Safe: safe, To: target, Value: big.NewInt(7), Data: nil, Operation: 0,
		SafeTxGas: big.NewInt(0), BaseGas: big.NewInt(0), GasPrice: big.NewInt(0),
		GasToken:       "0x0000000000000000000000000000000000000000",
		RefundReceiver: "0x0000000000000000000000000000000000000000",
		Nonce:          big.NewInt(0),
	}
	accessorCalldata, err := encodeSafeAccessorSimulateV04(tx)
	if err != nil {
		t.Fatal(err)
	}
	root := callTracerFrameV04{
		Type: "CALL", From: safeTraceCallerV04, To: safe, Input: "0x", Value: "0x0",
		Calls: []callTracerFrameV04{{
			Type: "DELEGATECALL", From: safe, To: accessor, Input: "0x" + hex.EncodeToString(accessorCalldata), Value: "0x0",
			Calls: []callTracerFrameV04{{Type: "CALL", From: safe, To: target, Input: "0x", Value: "0x7"}},
		}},
	}
	subtree := findSafeAccessorFrameV04(root, safe, accessor)
	if subtree == nil {
		t.Fatal("accessor subtree not found")
	}
	frames := []SafeTraceFrame{}
	if err := appendSafeTraceFramesV04(&frames, *subtree, 0); err != nil {
		t.Fatal(err)
	}
	trace := SafeTraceEvidence{RootSafe: safe, Frames: frames}
	trace.TraceSHA256 = safeTraceDigest(trace)
	if !(SafeAccessorSemanticsVerifier{Accessor: accessor}).Verify(tx, trace) {
		t.Fatal("converted callTracer evidence did not prove Safe accessor semantics")
	}
}

func TestAnvilSafeSimulationEngineV04RejectsUnsupportedEffects(t *testing.T) {
	engine := AnvilSafeSimulationEngine{AnvilPath: "/not-used", ForkURL: "http://127.0.0.1:1", Accessor: "0x2222222222222222222222222222222222222222"}
	tx := SafeTransaction{
		ChainID: 1, Safe: "0x1111111111111111111111111111111111111111", To: "0x3333333333333333333333333333333333333333",
		Value: big.NewInt(0), Data: []byte{0x01}, Operation: 0,
		SafeTxGas: big.NewInt(0), BaseGas: big.NewInt(0), GasPrice: big.NewInt(0),
		GasToken: "0x0000000000000000000000000000000000000000", RefundReceiver: "0x0000000000000000000000000000000000000000", Nonce: big.NewInt(0),
	}
	_, err := engine.ExecuteExactSafe(context.Background(), executioncontainment.CellInput{ChainID: 1, Target: tx.To}, tx)
	if err == nil || !strings.Contains(err.Error(), "native CALL with empty calldata") {
		t.Fatalf("unsupported calldata error=%v", err)
	}
	tx.Data = nil
	tx.Operation = 1
	_, err = engine.ExecuteExactSafe(context.Background(), executioncontainment.CellInput{ChainID: 1, Target: tx.To}, tx)
	if err == nil || !strings.Contains(err.Error(), "native CALL with empty calldata") {
		t.Fatalf("unsupported delegatecall error=%v", err)
	}
}

func TestAnvilSafeSimulationEngineV04Integration(t *testing.T) {
	if os.Getenv("KOSCHEI_SAFE_ANVIL_INTEGRATION") != "1" {
		t.Skip("real Anvil integration is opt-in")
	}
	anvilPath := mustEnvV04(t, "KOSCHEI_ANVIL_PATH")
	forkURL := mustEnvV04(t, "KOSCHEI_SAFE_FORK_URL")
	safe := mustEnvV04(t, "KOSCHEI_SAFE_ADDRESS")
	accessor := mustEnvV04(t, "KOSCHEI_SAFE_ACCESSOR_ADDRESS")
	target := mustEnvV04(t, "KOSCHEI_SAFE_TARGET_ADDRESS")
	blockNumber, err := strconv.ParseUint(mustEnvV04(t, "KOSCHEI_SAFE_BLOCK_NUMBER"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	blockHash := strings.TrimPrefix(mustEnvV04(t, "KOSCHEI_SAFE_BLOCK_HASH"), "0x")
	runnerSHA := strings.TrimPrefix(mustEnvV04(t, "KOSCHEI_ANVIL_SHA256"), "0x")
	chainID, err := strconv.ParseUint(mustEnvV04(t, "KOSCHEI_SAFE_CHAIN_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	engine := AnvilSafeSimulationEngine{
		AnvilPath: anvilPath, ForkURL: forkURL, Accessor: accessor,
		StartupTimeout: 20 * time.Second, RPCTimeout: 10 * time.Second,
	}
	tx := SafeTransaction{
		ChainID: chainID, Safe: safe, To: target, Value: new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), Data: nil, Operation: 0,
		SafeTxGas: big.NewInt(0), BaseGas: big.NewInt(0), GasPrice: big.NewInt(0),
		GasToken: "0x0000000000000000000000000000000000000000", RefundReceiver: "0x0000000000000000000000000000000000000000", Nonce: big.NewInt(0),
	}
	backend := PinnedSafeBackend{Engine: engine, Accessor: accessor}
	evidence, err := backend.ExecuteSafe(context.Background(), executioncontainment.CellInput{
		ChainID: chainID, BlockNumber: blockNumber, BlockHash: blockHash, Target: target, ApprovedRunnerSHA256: runnerSHA,
	}, tx)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.PreStateSHA256 == evidence.PostStateSHA256 {
		t.Fatal("real isolated execution did not change bound Safe state")
	}
	if len(evidence.AssetMovements) != 1 || evidence.AssetMovements[0].Amount != tx.Value.String() || normalizeAddress(evidence.AssetMovements[0].To) != normalizeAddress(target) {
		t.Fatalf("unexpected movement evidence: %#v", evidence.AssetMovements)
	}
	if !(SafeAccessorSemanticsVerifier{Accessor: accessor}).Verify(tx, evidence.Trace) {
		t.Fatal("real Anvil trace did not prove Safe accessor semantics")
	}
	if evidence.Before.Threshold != evidence.After.Threshold || !equalAddressSets(evidence.Before.Owners, evidence.After.Owners) {
		t.Fatal("native CALL unexpectedly changed Safe authority")
	}
}

func mustEnvV04(t *testing.T, key string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		t.Fatalf("%s is required", key)
	}
	return value
}

func sha256HexV04(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
