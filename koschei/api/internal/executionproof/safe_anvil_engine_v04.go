package executionproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/executioncontainment"
)

const SafeAnvilEngineVersionV04 = "koschei-safe-anvil-engine/v0.4"

const (
	safeFallbackHandlerStorageSlotV04 = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5"
	safeGuardStorageSlotV04           = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"
	safeSentinelModulesV04            = "0x0000000000000000000000000000000000000001"
	safeTraceCallerV04                = "0x000000000000000000000000000000000000dEaD"
)

// AnvilSafeSimulationEngine is a concrete observation-only Safe engine for the
// component validation plane. v0.4 is intentionally narrow: it accepts only a
// native-asset CALL with empty calldata. Delegatecall and token calldata remain
// fail-closed until their post-state/effect collectors are independently bound.
//
// ExecuteExactSafe performs two bound executions on one pinned local Anvil fork:
//  1. debug_traceCall through Safe.simulateAndRevert -> SimulateTxAccessor,
//     proving the exact Safe delegatecall/call path without committing state;
//  2. an isolated materialization CALL from the impersonated Safe using the
//     exact target/value/data, allowing post-state/effect evidence collection.
//
// The second execution is valid only for Operation=CALL and empty calldata. It
// is never production forwarding authority and the child Anvil listens only on
// 127.0.0.1.
type AnvilSafeSimulationEngine struct {
	AnvilPath      string
	ForkURL        string
	Accessor       string
	StartupTimeout time.Duration
	RPCTimeout     time.Duration
}

func (e AnvilSafeSimulationEngine) PinnedBlock(ctx context.Context, chainID, blockNumber uint64) (string, error) {
	client, err := e.upstreamClientV04()
	if err != nil {
		return "", err
	}
	observedChainID, err := client.chainID(ctx)
	if err != nil || observedChainID != chainID {
		return "", errors.New("Safe Anvil upstream chain identity mismatch")
	}
	return client.blockHash(ctx, blockNumber)
}

func (e AnvilSafeSimulationEngine) RunnerSHA256(context.Context) (string, error) {
	if strings.TrimSpace(e.AnvilPath) == "" {
		return "", errors.New("Anvil runner path is required")
	}
	return fileSHA256(e.AnvilPath)
}

func (e AnvilSafeSimulationEngine) SnapshotSafe(ctx context.Context, chainID, blockNumber uint64, safe string) (SafeAuthoritySnapshot, string, error) {
	client, err := e.upstreamClientV04()
	if err != nil {
		return SafeAuthoritySnapshot{}, "", err
	}
	observedChainID, err := client.chainID(ctx)
	if err != nil || observedChainID != chainID {
		return SafeAuthoritySnapshot{}, "", errors.New("Safe snapshot chain identity mismatch")
	}
	if _, err := client.blockHash(ctx, blockNumber); err != nil {
		return SafeAuthoritySnapshot{}, "", fmt.Errorf("resolve Safe snapshot block: %w", err)
	}
	state, err := snapshotSafeStateV04(ctx, client, safe, fmt.Sprintf("0x%x", blockNumber))
	if err != nil {
		return SafeAuthoritySnapshot{}, "", err
	}
	return state.Authority, state.StateSHA256, nil
}

func (e AnvilSafeSimulationEngine) ExecuteExactSafe(ctx context.Context, input executioncontainment.CellInput, tx SafeTransaction) (SafeSimulationResult, error) {
	if strings.TrimSpace(e.AnvilPath) == "" || strings.TrimSpace(e.ForkURL) == "" || !validAddress(e.Accessor) {
		return SafeSimulationResult{}, errors.New("Safe Anvil engine configuration is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return SafeSimulationResult{}, err
	}
	if !validSafeTransaction(tx) || tx.Operation != 0 || len(tx.Data) != 0 {
		return SafeSimulationResult{}, errors.New("Safe Anvil v0.4 supports only native CALL with empty calldata")
	}
	if tx.ChainID != input.ChainID || !strings.EqualFold(normalizeAddress(tx.To), normalizeAddress(input.Target)) {
		return SafeSimulationResult{}, errors.New("Safe Anvil transaction/input identity mismatch")
	}

	port, err := reserveLocalPort()
	if err != nil {
		return SafeSimulationResult{}, fmt.Errorf("reserve Safe Anvil port: %w", err)
	}
	rpcURL := "http://127.0.0.1:" + strconv.Itoa(port)
	cmd := exec.CommandContext(ctx, e.AnvilPath,
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--fork-url", e.ForkURL,
		"--fork-block-number", strconv.FormatUint(input.BlockNumber, 10),
		"--block-base-fee-per-gas", "0",
		"--gas-price", "0",
		"--disable-min-priority-fee",
		"--steps-tracing",
		"--silent",
	)
	cmd.Env = minimalRunnerEnv(os.Environ())
	var stderr bytes.Buffer
	cmd.Stdout = nil
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return SafeSimulationResult{}, fmt.Errorf("start Safe Anvil: %w", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	client := &evmRPCClient{url: rpcURL, http: &http.Client{Timeout: durationOr(e.RPCTimeout, 5*time.Second)}}
	if err := waitForAnvil(ctx, client, durationOr(e.StartupTimeout, 15*time.Second)); err != nil {
		if stderr.Len() != 0 {
			return SafeSimulationResult{}, fmt.Errorf("Safe Anvil startup: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return SafeSimulationResult{}, err
	}
	chainID, err := client.chainID(ctx)
	if err != nil || chainID != input.ChainID {
		return SafeSimulationResult{}, errors.New("Safe Anvil fork chain identity mismatch")
	}
	blockHash, err := client.blockHash(ctx, input.BlockNumber)
	if err != nil || !equalHex32(blockHash, input.BlockHash) {
		return SafeSimulationResult{}, errors.New("Safe Anvil fork block identity mismatch")
	}

	pre, err := snapshotSafeStateV04(ctx, client, tx.Safe, "latest")
	if err != nil {
		return SafeSimulationResult{}, fmt.Errorf("snapshot Safe fork pre-state: %w", err)
	}
	targetBalanceBefore, err := client.balanceAtV04(ctx, tx.To, "latest")
	if err != nil {
		return SafeSimulationResult{}, fmt.Errorf("snapshot target pre-balance: %w", err)
	}

	trace, err := client.traceSafeSimulationV04(ctx, tx, e.Accessor)
	if err != nil {
		return SafeSimulationResult{}, fmt.Errorf("trace Safe accessor execution: %w", err)
	}
	if !(SafeAccessorSemanticsVerifier{Accessor: e.Accessor}).Verify(tx, trace) {
		return SafeSimulationResult{}, errors.New("Safe Anvil accessor trace failed semantic verification")
	}

	if err := client.call(ctx, "anvil_impersonateAccount", []any{normalizeAddress(tx.Safe)}, nil); err != nil {
		return SafeSimulationResult{}, fmt.Errorf("impersonate Safe for isolated state materialization: %w", err)
	}
	defer func() {
		_ = client.call(context.Background(), "anvil_stopImpersonatingAccount", []any{normalizeAddress(tx.Safe)}, nil)
	}()

	txHash, err := client.sendNativeMaterializationV04(ctx, tx)
	if err != nil {
		return SafeSimulationResult{}, fmt.Errorf("materialize exact Safe CALL on isolated fork: %w", err)
	}
	if err := client.requireSuccessfulReceipt(ctx, txHash); err != nil {
		return SafeSimulationResult{}, fmt.Errorf("isolated Safe materialization failed: %w", err)
	}
	receiptSHA, err := client.transactionReceiptDigest(ctx, txHash)
	if err != nil {
		return SafeSimulationResult{}, fmt.Errorf("bind Safe materialization receipt: %w", err)
	}

	post, err := snapshotSafeStateV04(ctx, client, tx.Safe, "latest")
	if err != nil {
		return SafeSimulationResult{}, fmt.Errorf("snapshot Safe fork post-state: %w", err)
	}
	targetBalanceAfter, err := client.balanceAtV04(ctx, tx.To, "latest")
	if err != nil {
		return SafeSimulationResult{}, fmt.Errorf("snapshot target post-balance: %w", err)
	}

	movements := []SafeAssetMovement{}
	if tx.Value.Sign() > 0 {
		movements = append(movements, SafeAssetMovement{
			Kind:   "native",
			From:   normalizeAddress(tx.Safe),
			To:     normalizeAddress(tx.To),
			Amount: tx.Value.String(),
		})
	}
	effectSHA, err := safeMaterializedEffectDigestV04(safeMaterializedEffectV04{
		Version:             SafeAnvilEngineVersionV04,
		TransactionHash:     txHash,
		ReceiptSHA256:       receiptSHA,
		TraceSHA256:         strings.TrimPrefix(trace.TraceSHA256, "0x"),
		SafeBalanceBefore:   pre.Balance,
		SafeBalanceAfter:    post.Balance,
		TargetBalanceBefore: targetBalanceBefore,
		TargetBalanceAfter:  targetBalanceAfter,
		Movements:           movements,
	})
	if err != nil {
		return SafeSimulationResult{}, err
	}

	return SafeSimulationResult{
		PostAuthority:   post.Authority,
		PostStateSHA256: post.StateSHA256,
		EffectSetSHA256: effectSHA,
		AssetMovements:  movements,
		Trace:           trace,
	}, nil
}

func (e AnvilSafeSimulationEngine) upstreamClientV04() (*evmRPCClient, error) {
	if strings.TrimSpace(e.ForkURL) == "" {
		return nil, errors.New("Safe Anvil fork URL is required")
	}
	return &evmRPCClient{url: strings.TrimSpace(e.ForkURL), http: &http.Client{Timeout: durationOr(e.RPCTimeout, 5*time.Second)}}, nil
}

type safeStateSnapshotV04 struct {
	Version     string                `json:"version"`
	Safe        string                `json:"safe"`
	Authority   SafeAuthoritySnapshot `json:"authority"`
	Balance     string                `json:"balance"`
	Nonce       string                `json:"nonce"`
	StateSHA256 string                `json:"state_sha256"`
}

func snapshotSafeStateV04(ctx context.Context, client *evmRPCClient, safe, blockTag string) (safeStateSnapshotV04, error) {
	if client == nil || !validAddress(safe) {
		return safeStateSnapshotV04{}, errors.New("invalid Safe snapshot target")
	}
	safe = normalizeAddress(safe)
	ownersData, err := client.ethCallAtV04(ctx, safe, abiSelectorHexV04("getOwners()"), blockTag)
	if err != nil {
		return safeStateSnapshotV04{}, fmt.Errorf("get Safe owners: %w", err)
	}
	owners, err := decodeABIAddressArrayV04(ownersData, 0)
	if err != nil || len(owners) == 0 {
		return safeStateSnapshotV04{}, errors.New("decode Safe owners")
	}
	thresholdData, err := client.ethCallAtV04(ctx, safe, abiSelectorHexV04("getThreshold()"), blockTag)
	if err != nil {
		return safeStateSnapshotV04{}, fmt.Errorf("get Safe threshold: %w", err)
	}
	threshold, err := decodeABIUint64V04(thresholdData, 0)
	if err != nil || threshold == 0 || threshold > uint64(len(owners)) {
		return safeStateSnapshotV04{}, errors.New("decode Safe threshold")
	}
	modules, err := client.safeModulesAtV04(ctx, safe, blockTag)
	if err != nil {
		return safeStateSnapshotV04{}, err
	}
	guardWord, err := client.storageAtV04(ctx, safe, safeGuardStorageSlotV04, blockTag)
	if err != nil {
		return safeStateSnapshotV04{}, fmt.Errorf("get Safe guard slot: %w", err)
	}
	fallbackWord, err := client.storageAtV04(ctx, safe, safeFallbackHandlerStorageSlotV04, blockTag)
	if err != nil {
		return safeStateSnapshotV04{}, fmt.Errorf("get Safe fallback slot: %w", err)
	}
	implementationWord, err := client.storageAtV04(ctx, safe, "0x0", blockTag)
	if err != nil {
		return safeStateSnapshotV04{}, fmt.Errorf("get Safe implementation slot: %w", err)
	}
	guard, err := addressFromWordV04(guardWord)
	if err != nil {
		return safeStateSnapshotV04{}, err
	}
	fallback, err := addressFromWordV04(fallbackWord)
	if err != nil {
		return safeStateSnapshotV04{}, err
	}
	implementation, err := addressFromWordV04(implementationWord)
	if err != nil {
		return safeStateSnapshotV04{}, err
	}
	if implementation == "0x0000000000000000000000000000000000000000" {
		implementation = safe
	}
	codeHex, err := client.codeAtV04(ctx, implementation, blockTag)
	if err != nil {
		return safeStateSnapshotV04{}, fmt.Errorf("get Safe implementation code: %w", err)
	}
	code, err := decodeHexBytesV04(codeHex)
	if err != nil || len(code) == 0 {
		return safeStateSnapshotV04{}, errors.New("Safe implementation code is unavailable")
	}
	codeHash := keccak256(code)
	balance, err := client.balanceAtV04(ctx, safe, blockTag)
	if err != nil {
		return safeStateSnapshotV04{}, fmt.Errorf("get Safe balance: %w", err)
	}
	nonceData, err := client.ethCallAtV04(ctx, safe, abiSelectorHexV04("nonce()"), blockTag)
	if err != nil {
		return safeStateSnapshotV04{}, fmt.Errorf("get Safe nonce: %w", err)
	}
	nonce, err := decodeABIUintV04(nonceData, 0)
	if err != nil {
		return safeStateSnapshotV04{}, errors.New("decode Safe nonce")
	}

	for i := range owners {
		owners[i] = normalizeAddress(owners[i])
	}
	for i := range modules {
		modules[i] = normalizeAddress(modules[i])
	}
	sort.Strings(owners)
	sort.Strings(modules)
	authority := SafeAuthoritySnapshot{
		Owners:          owners,
		Threshold:       threshold,
		Modules:         modules,
		Guard:           guard,
		FallbackHandler: fallback,
		Implementation:  implementation,
		CodeHash:        "0x" + hex.EncodeToString(codeHash[:]),
	}
	if !validAuthoritySnapshot(authority) {
		return safeStateSnapshotV04{}, errors.New("Safe authority snapshot failed validation")
	}
	state := safeStateSnapshotV04{
		Version:   SafeAnvilEngineVersionV04,
		Safe:      safe,
		Authority: authority,
		Balance:   balance,
		Nonce:     nonce.String(),
	}
	stateDigest := state
	stateDigest.StateSHA256 = ""
	encoded, err := json.Marshal(stateDigest)
	if err != nil {
		return safeStateSnapshotV04{}, err
	}
	sum := sha256.Sum256(encoded)
	state.StateSHA256 = hex.EncodeToString(sum[:])
	return state, nil
}

func (c *evmRPCClient) ethCallAtV04(ctx context.Context, to, data, blockTag string) (string, error) {
	var result string
	if blockTag == "" {
		blockTag = "latest"
	}
	if err := c.call(ctx, "eth_call", []any{map[string]any{"to": normalizeAddress(to), "data": data}, blockTag}, &result); err != nil {
		return "", err
	}
	if _, err := decodeHexBytesV04(result); err != nil {
		return "", err
	}
	return strings.ToLower(result), nil
}

func (c *evmRPCClient) storageAtV04(ctx context.Context, address, slot, blockTag string) (string, error) {
	var result string
	if blockTag == "" {
		blockTag = "latest"
	}
	if err := c.call(ctx, "eth_getStorageAt", []any{normalizeAddress(address), slot, blockTag}, &result); err != nil {
		return "", err
	}
	bytes, err := decodeHexBytesV04(result)
	if err != nil || len(bytes) > 32 {
		return "", errors.New("invalid EVM storage word")
	}
	padded := make([]byte, 32)
	copy(padded[32-len(bytes):], bytes)
	return "0x" + hex.EncodeToString(padded), nil
}

func (c *evmRPCClient) codeAtV04(ctx context.Context, address, blockTag string) (string, error) {
	var result string
	if blockTag == "" {
		blockTag = "latest"
	}
	if err := c.call(ctx, "eth_getCode", []any{normalizeAddress(address), blockTag}, &result); err != nil {
		return "", err
	}
	if _, err := decodeHexBytesV04(result); err != nil {
		return "", err
	}
	return strings.ToLower(result), nil
}

func (c *evmRPCClient) balanceAtV04(ctx context.Context, address, blockTag string) (string, error) {
	var result string
	if blockTag == "" {
		blockTag = "latest"
	}
	if err := c.call(ctx, "eth_getBalance", []any{normalizeAddress(address), blockTag}, &result); err != nil {
		return "", err
	}
	value := new(big.Int)
	if _, ok := value.SetString(strings.TrimPrefix(result, "0x"), 16); !ok || value.Sign() < 0 {
		return "", errors.New("invalid EVM balance")
	}
	return value.String(), nil
}

func (c *evmRPCClient) safeModulesAtV04(ctx context.Context, safe, blockTag string) ([]string, error) {
	start := safeSentinelModulesV04
	modules := make([]string, 0)
	seen := map[string]struct{}{}
	for page := 0; page < 16; page++ {
		calldata, err := encodeGetModulesPaginatedV04(start, 128)
		if err != nil {
			return nil, err
		}
		result, err := c.ethCallAtV04(ctx, safe, calldata, blockTag)
		if err != nil {
			return nil, fmt.Errorf("get Safe modules: %w", err)
		}
		pageModules, next, err := decodeModulesPageV04(result)
		if err != nil {
			return nil, err
		}
		for _, module := range pageModules {
			module = normalizeAddress(module)
			if _, exists := seen[module]; exists {
				return nil, errors.New("duplicate Safe module in pagination")
			}
			seen[module] = struct{}{}
			modules = append(modules, module)
		}
		if normalizeAddress(next) == normalizeAddress(safeSentinelModulesV04) {
			return modules, nil
		}
		if !validAddress(next) || normalizeAddress(next) == normalizeAddress(start) {
			return nil, errors.New("invalid Safe module pagination cursor")
		}
		start = next
	}
	return nil, errors.New("Safe module pagination exceeded bound")
}

type callTracerFrameV04 struct {
	Type  string               `json:"type"`
	From  string               `json:"from"`
	To    string               `json:"to"`
	Value string               `json:"value"`
	Input string               `json:"input"`
	Error string               `json:"error"`
	Calls []callTracerFrameV04 `json:"calls"`
}

func (c *evmRPCClient) traceSafeSimulationV04(ctx context.Context, tx SafeTransaction, accessor string) (SafeTraceEvidence, error) {
	accessorCalldata, err := encodeSafeAccessorSimulateV04(tx)
	if err != nil {
		return SafeTraceEvidence{}, err
	}
	outerCalldata, err := encodeSimulateAndRevertV04(accessor, accessorCalldata)
	if err != nil {
		return SafeTraceEvidence{}, err
	}
	var root callTracerFrameV04
	call := map[string]any{
		"from": safeTraceCallerV04,
		"to":   normalizeAddress(tx.Safe),
		"data": "0x" + hex.EncodeToString(outerCalldata),
	}
	config := map[string]any{"tracer": "callTracer"}
	if err := c.call(ctx, "debug_traceCall", []any{call, "latest", config}, &root); err != nil {
		return SafeTraceEvidence{}, err
	}
	subtree := findSafeAccessorFrameV04(root, tx.Safe, accessor)
	if subtree == nil {
		return SafeTraceEvidence{}, errors.New("Safe accessor delegatecall was not observed")
	}
	frames := make([]SafeTraceFrame, 0, 4)
	if err := appendSafeTraceFramesV04(&frames, *subtree, 0); err != nil {
		return SafeTraceEvidence{}, err
	}
	trace := SafeTraceEvidence{RootSafe: normalizeAddress(tx.Safe), Frames: frames, Truncated: false}
	trace.TraceSHA256 = safeTraceDigest(trace)
	return trace, nil
}

func findSafeAccessorFrameV04(frame callTracerFrameV04, safe, accessor string) *callTracerFrameV04 {
	if strings.EqualFold(strings.TrimSpace(frame.Type), "DELEGATECALL") &&
		normalizeAddress(frame.From) == normalizeAddress(safe) && normalizeAddress(frame.To) == normalizeAddress(accessor) {
		copyFrame := frame
		return &copyFrame
	}
	for _, child := range frame.Calls {
		if found := findSafeAccessorFrameV04(child, safe, accessor); found != nil {
			return found
		}
	}
	return nil
}

func appendSafeTraceFramesV04(out *[]SafeTraceFrame, frame callTracerFrameV04, depth uint64) error {
	if !validAddress(frame.From) || !validAddress(frame.To) {
		return errors.New("call tracer frame has invalid address identity")
	}
	input, err := decodeHexBytesV04(frame.Input)
	if err != nil {
		return errors.New("call tracer frame has invalid input")
	}
	inputSum := sha256.Sum256(input)
	value, err := hexQuantityToDecimalV04(frame.Value)
	if err != nil {
		return err
	}
	*out = append(*out, SafeTraceFrame{
		Depth:       depth,
		Type:        strings.ToLower(strings.TrimSpace(frame.Type)),
		From:        normalizeAddress(frame.From),
		To:          normalizeAddress(frame.To),
		InputSHA256: hex.EncodeToString(inputSum[:]),
		Value:       value,
		Success:     strings.TrimSpace(frame.Error) == "",
	})
	for _, child := range frame.Calls {
		if err := appendSafeTraceFramesV04(out, child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (c *evmRPCClient) sendNativeMaterializationV04(ctx context.Context, tx SafeTransaction) (string, error) {
	var txHash string
	call := map[string]any{
		"from":     normalizeAddress(tx.Safe),
		"to":       normalizeAddress(tx.To),
		"value":    "0x" + tx.Value.Text(16),
		"data":     "0x",
		"gas":      "0x100000",
		"gasPrice": "0x0",
	}
	if err := c.call(ctx, "eth_sendTransaction", []any{call}, &txHash); err != nil {
		return "", err
	}
	if !validHex32(txHash) {
		return "", errors.New("invalid isolated Safe transaction hash")
	}
	return normalizeHex32(txHash), nil
}

type safeMaterializedEffectV04 struct {
	Version             string              `json:"version"`
	TransactionHash     string              `json:"transaction_hash"`
	ReceiptSHA256       string              `json:"receipt_sha256"`
	TraceSHA256         string              `json:"trace_sha256"`
	SafeBalanceBefore   string              `json:"safe_balance_before"`
	SafeBalanceAfter    string              `json:"safe_balance_after"`
	TargetBalanceBefore string              `json:"target_balance_before"`
	TargetBalanceAfter  string              `json:"target_balance_after"`
	Movements           []SafeAssetMovement `json:"movements"`
}

func safeMaterializedEffectDigestV04(effect safeMaterializedEffectV04) (string, error) {
	effect.TransactionHash = normalizeHex32(effect.TransactionHash)
	effect.ReceiptSHA256 = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(effect.ReceiptSHA256), "0x"))
	effect.TraceSHA256 = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(effect.TraceSHA256), "0x"))
	encoded, err := json.Marshal(effect)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func encodeSafeAccessorSimulateV04(tx SafeTransaction) ([]byte, error) {
	if !validSafeTransaction(tx) {
		return nil, errors.New("invalid Safe transaction")
	}
	selector := keccak256([]byte("simulate(address,uint256,bytes,uint8)"))
	toWord, err := addressWord(tx.To)
	if err != nil {
		return nil, err
	}
	valueWord, err := uintWord(tx.Value)
	if err != nil {
		return nil, err
	}
	offsetWord, _ := uintWord(big.NewInt(128))
	opWord, _ := uintWord(new(big.Int).SetUint64(uint64(tx.Operation)))
	lengthWord, _ := uintWord(new(big.Int).SetUint64(uint64(len(tx.Data))))
	padded := ((len(tx.Data) + 31) / 32) * 32
	calldata := make([]byte, 0, 4+32*5+padded)
	calldata = append(calldata, selector[:4]...)
	calldata = append(calldata, toWord[:]...)
	calldata = append(calldata, valueWord[:]...)
	calldata = append(calldata, offsetWord[:]...)
	calldata = append(calldata, opWord[:]...)
	calldata = append(calldata, lengthWord[:]...)
	calldata = append(calldata, tx.Data...)
	calldata = append(calldata, make([]byte, padded-len(tx.Data))...)
	return calldata, nil
}

func encodeSimulateAndRevertV04(accessor string, payload []byte) ([]byte, error) {
	if !validAddress(accessor) {
		return nil, errors.New("invalid Safe accessor")
	}
	selector := keccak256([]byte("simulateAndRevert(address,bytes)"))
	accessorWord, err := addressWord(accessor)
	if err != nil {
		return nil, err
	}
	offsetWord, _ := uintWord(big.NewInt(64))
	lengthWord, _ := uintWord(new(big.Int).SetUint64(uint64(len(payload))))
	padded := ((len(payload) + 31) / 32) * 32
	calldata := make([]byte, 0, 4+32*3+padded)
	calldata = append(calldata, selector[:4]...)
	calldata = append(calldata, accessorWord[:]...)
	calldata = append(calldata, offsetWord[:]...)
	calldata = append(calldata, lengthWord[:]...)
	calldata = append(calldata, payload...)
	calldata = append(calldata, make([]byte, padded-len(payload))...)
	return calldata, nil
}

func abiSelectorHexV04(signature string) string {
	hash := keccak256([]byte(signature))
	return "0x" + hex.EncodeToString(hash[:4])
}

func encodeGetModulesPaginatedV04(start string, pageSize uint64) (string, error) {
	startWord, err := addressWord(start)
	if err != nil {
		return "", err
	}
	pageWord, err := uintWord(new(big.Int).SetUint64(pageSize))
	if err != nil {
		return "", err
	}
	selector := keccak256([]byte("getModulesPaginated(address,uint256)"))
	calldata := append([]byte{}, selector[:4]...)
	calldata = append(calldata, startWord[:]...)
	calldata = append(calldata, pageWord[:]...)
	return "0x" + hex.EncodeToString(calldata), nil
}

func decodeModulesPageV04(value string) ([]string, string, error) {
	data, err := decodeHexBytesV04(value)
	if err != nil || len(data) < 64 {
		return nil, "", errors.New("invalid Safe modules response")
	}
	offset, err := abiWordUint64V04(data[:32])
	if err != nil {
		return nil, "", err
	}
	modules, err := decodeABIAddressArrayBytesV04(data, int(offset))
	if err != nil {
		return nil, "", err
	}
	next, err := addressFromWordBytesV04(data[32:64])
	if err != nil {
		return nil, "", err
	}
	return modules, next, nil
}

func decodeABIAddressArrayV04(value string, headWord int) ([]string, error) {
	data, err := decodeHexBytesV04(value)
	if err != nil || len(data) < (headWord+1)*32 {
		return nil, errors.New("invalid ABI address array")
	}
	offset, err := abiWordUint64V04(data[headWord*32 : (headWord+1)*32])
	if err != nil {
		return nil, err
	}
	return decodeABIAddressArrayBytesV04(data, int(offset))
}

func decodeABIAddressArrayBytesV04(data []byte, offset int) ([]string, error) {
	if offset < 0 || offset+32 > len(data) {
		return nil, errors.New("ABI address array offset is invalid")
	}
	count, err := abiWordUint64V04(data[offset : offset+32])
	if err != nil || count > 4096 {
		return nil, errors.New("ABI address array length is invalid")
	}
	end := offset + 32 + int(count)*32
	if end > len(data) {
		return nil, errors.New("ABI address array is truncated")
	}
	out := make([]string, 0, count)
	for i := 0; i < int(count); i++ {
		address, err := addressFromWordBytesV04(data[offset+32+i*32 : offset+64+i*32])
		if err != nil {
			return nil, err
		}
		out = append(out, address)
	}
	return out, nil
}

func decodeABIUint64V04(value string, word int) (uint64, error) {
	data, err := decodeHexBytesV04(value)
	if err != nil || len(data) < (word+1)*32 {
		return 0, errors.New("invalid ABI uint response")
	}
	return abiWordUint64V04(data[word*32 : (word+1)*32])
}

func decodeABIUintV04(value string, word int) (*big.Int, error) {
	data, err := decodeHexBytesV04(value)
	if err != nil || len(data) < (word+1)*32 {
		return nil, errors.New("invalid ABI uint response")
	}
	return new(big.Int).SetBytes(data[word*32 : (word+1)*32]), nil
}

func abiWordUint64V04(word []byte) (uint64, error) {
	if len(word) != 32 {
		return 0, errors.New("invalid ABI word")
	}
	value := new(big.Int).SetBytes(word)
	if !value.IsUint64() {
		return 0, errors.New("ABI word exceeds uint64")
	}
	return value.Uint64(), nil
}

func addressFromWordV04(value string) (string, error) {
	word, err := decodeHexBytesV04(value)
	if err != nil {
		return "", err
	}
	if len(word) > 32 {
		return "", errors.New("invalid address storage word")
	}
	padded := make([]byte, 32)
	copy(padded[32-len(word):], word)
	return addressFromWordBytesV04(padded)
}

func addressFromWordBytesV04(word []byte) (string, error) {
	if len(word) != 32 {
		return "", errors.New("invalid address ABI word")
	}
	return "0x" + hex.EncodeToString(word[12:]), nil
}

func decodeHexBytesV04(value string) ([]byte, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if len(value)%2 != 0 {
		return nil, errors.New("odd-length hex bytes")
	}
	if value == "" {
		return []byte{}, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func hexQuantityToDecimalV04(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "0", nil
	}
	value = strings.TrimPrefix(value, "0x")
	amount := new(big.Int)
	if _, ok := amount.SetString(value, 16); !ok || amount.Sign() < 0 {
		return "", errors.New("invalid EVM value quantity")
	}
	return amount.String(), nil
}
