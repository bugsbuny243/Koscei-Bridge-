package executionproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// EVMForkInvariantEvaluator evaluates the approved invariant set against the
// post-execution state of one isolated local fork. It must not hold signing
// authority or production private keys.
type EVMForkInvariantEvaluator interface {
	EvaluatePostState(ctx context.Context, rpcURL string, request PreparedVerifiedForkRequest, txHash string) ([]InvariantCheck, error)
}

type AnvilForkBackend struct {
	AnvilPath      string
	ForkURL        string
	StartupTimeout time.Duration
	RPCTimeout     time.Duration
	Evaluator      EVMForkInvariantEvaluator
}

func (b AnvilForkBackend) ExecuteVerifiedFork(ctx context.Context, request PreparedVerifiedForkRequest) (VerifiedForkBackendResult, error) {
	if strings.TrimSpace(b.AnvilPath) == "" || strings.TrimSpace(b.ForkURL) == "" || b.Evaluator == nil {
		return VerifiedForkBackendResult{}, errVerifiedForkBackend
	}
	if err := ctx.Err(); err != nil {
		return VerifiedForkBackendResult{}, err
	}

	runnerSHA, err := fileSHA256(b.AnvilPath)
	if err != nil {
		return VerifiedForkBackendResult{}, fmt.Errorf("hash anvil runner: %w", err)
	}

	port, err := reserveLocalPort()
	if err != nil {
		return VerifiedForkBackendResult{}, fmt.Errorf("reserve local anvil port: %w", err)
	}
	rpcURL := "http://127.0.0.1:" + strconv.Itoa(port)

	cmd := exec.CommandContext(ctx, b.AnvilPath,
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--fork-url", b.ForkURL,
		"--fork-block-number", strconv.FormatUint(request.Simulation.ReferenceBlock, 10),
		"--silent",
	)
	cmd.Env = minimalRunnerEnv(os.Environ())
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return VerifiedForkBackendResult{}, fmt.Errorf("start anvil: %w", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	client := &evmRPCClient{url: rpcURL, http: &http.Client{Timeout: durationOr(b.RPCTimeout, 5*time.Second)}}
	if err := waitForAnvil(ctx, client, durationOr(b.StartupTimeout, 15*time.Second)); err != nil {
		if stderr.Len() != 0 {
			return VerifiedForkBackendResult{}, fmt.Errorf("anvil startup: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return VerifiedForkBackendResult{}, err
	}

	chainID, err := client.chainID(ctx)
	if err != nil || chainID != request.Simulation.ChainID {
		return VerifiedForkBackendResult{}, fmt.Errorf("fork chain identity mismatch")
	}
	blockHash, err := client.blockHash(ctx, request.Simulation.ReferenceBlock)
	if err != nil || !equalHex32(blockHash, request.Simulation.ReferenceBlockHash) {
		return VerifiedForkBackendResult{}, fmt.Errorf("fork reference block mismatch")
	}

	if err := client.callBool(ctx, "anvil_impersonateAccount", []any{request.Payload.From}); err != nil {
		return VerifiedForkBackendResult{}, fmt.Errorf("impersonate simulation sender: %w", err)
	}
	defer func() {
		_ = client.callBool(context.Background(), "anvil_stopImpersonatingAccount", []any{request.Payload.From})
	}()

	txHash, err := client.sendTransaction(ctx, request.Payload)
	if err != nil {
		return VerifiedForkBackendResult{}, fmt.Errorf("execute isolated fork transaction: %w", err)
	}
	if err := client.requireSuccessfulReceipt(ctx, txHash); err != nil {
		return VerifiedForkBackendResult{}, fmt.Errorf("isolated fork transaction failed: %w", err)
	}
	receiptSHA, err := client.transactionReceiptDigest(ctx, txHash)
	if err != nil {
		return VerifiedForkBackendResult{}, fmt.Errorf("bind isolated fork receipt: %w", err)
	}

	checks, err := b.Evaluator.EvaluatePostState(ctx, rpcURL, request, txHash)
	if err != nil {
		return VerifiedForkBackendResult{}, fmt.Errorf("evaluate fork invariants: %w", err)
	}
	payloadSHA, ok := evmPayloadDigest(request.Payload)
	if !ok {
		return VerifiedForkBackendResult{}, errVerifiedForkBackend
	}

	return VerifiedForkBackendResult{
		ObservedRunnerSHA256: runnerSHA,
		Simulation: ForkBackendResult{
			ChainID:                  chainID,
			ObservedReferenceBlock:   request.Simulation.ReferenceBlock,
			ObservedReferenceHash:    blockHash,
			ObservedPayloadSHA256:    payloadSHA,
			ObservedInvariantSetHash: request.Simulation.InvariantSetSHA256,
			Checks:                   checks,
		},
		Execution: ForkExecutionEvidence{
			TransactionHash:          txHash,
			TransactionReceiptSHA256: receiptSHA,
			InvariantEvidenceSHA256:  canonicalInvariantEvidenceDigest(checks),
		},
	}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func reserveLocalPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func minimalRunnerEnv(input []string) []string {
	allowed := []string{"PATH=", "HOME=", "TMPDIR=", "SSL_CERT_FILE=", "SSL_CERT_DIR="}
	out := make([]string, 0, len(allowed))
	for _, item := range input {
		for _, prefix := range allowed {
			if strings.HasPrefix(item, prefix) {
				out = append(out, item)
				break
			}
		}
	}
	return out
}

func durationOr(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func waitForAnvil(ctx context.Context, client *evmRPCClient, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := client.chainID(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("anvil startup timeout")
		case <-ticker.C:
		}
	}
}

type evmRPCClient struct {
	url  string
	http *http.Client
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *evmRPCClient) call(ctx context.Context, method string, params any, out any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rpc http status %d", resp.StatusCode)
	}
	var decoded rpcResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&decoded); err != nil {
		return err
	}
	if decoded.Error != nil {
		return fmt.Errorf("rpc %s: %d %s", method, decoded.Error.Code, decoded.Error.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(decoded.Result, out)
}

func (c *evmRPCClient) chainID(ctx context.Context) (uint64, error) {
	var value string
	if err := c.call(ctx, "eth_chainId", []any{}, &value); err != nil {
		return 0, err
	}
	value = strings.TrimPrefix(value, "0x")
	return strconv.ParseUint(value, 16, 64)
}

func (c *evmRPCClient) blockHash(ctx context.Context, block uint64) (string, error) {
	var result struct {
		Hash string `json:"hash"`
	}
	if err := c.call(ctx, "eth_getBlockByNumber", []any{fmt.Sprintf("0x%x", block), false}, &result); err != nil {
		return "", err
	}
	if !validHex32(result.Hash) {
		return "", errors.New("invalid block hash")
	}
	return normalizeHex32(result.Hash), nil
}

func (c *evmRPCClient) callBool(ctx context.Context, method string, params any) error {
	var ok bool
	if err := c.call(ctx, method, params, &ok); err != nil {
		return err
	}
	if !ok {
		return errors.New("rpc returned false")
	}
	return nil
}

func (c *evmRPCClient) sendTransaction(ctx context.Context, payload EVMPayload) (string, error) {
	var txHash string
	tx := map[string]any{"from": payload.From, "to": payload.To, "value": payload.ValueHex, "data": payload.DataHex}
	if err := c.call(ctx, "eth_sendTransaction", []any{tx}, &txHash); err != nil {
		return "", err
	}
	if !validHex32(txHash) {
		return "", errors.New("invalid transaction hash")
	}
	return normalizeHex32(txHash), nil
}

type canonicalEVMReceipt struct {
	TransactionHash   string            `json:"transaction_hash"`
	BlockHash         string            `json:"block_hash"`
	BlockNumber       string            `json:"block_number"`
	Status            string            `json:"status"`
	GasUsed           string            `json:"gas_used"`
	CumulativeGasUsed string            `json:"cumulative_gas_used"`
	ContractAddress   *string           `json:"contract_address"`
	Logs              []json.RawMessage `json:"logs"`
}

type rpcEVMReceipt struct {
	TransactionHash   string            `json:"transactionHash"`
	BlockHash         string            `json:"blockHash"`
	BlockNumber       string            `json:"blockNumber"`
	Status            string            `json:"status"`
	GasUsed           string            `json:"gasUsed"`
	CumulativeGasUsed string            `json:"cumulativeGasUsed"`
	ContractAddress   *string           `json:"contractAddress"`
	Logs              []json.RawMessage `json:"logs"`
}

var errEVMReceiptPending = errors.New("EVM transaction receipt pending")

func (c *evmRPCClient) transactionReceipt(ctx context.Context, txHash string) (canonicalEVMReceipt, error) {
	var wire rpcEVMReceipt
	if err := c.call(ctx, "eth_getTransactionReceipt", []any{txHash}, &wire); err != nil {
		return canonicalEVMReceipt{}, err
	}
	if wire.TransactionHash == "" && wire.BlockHash == "" {
		return canonicalEVMReceipt{}, errEVMReceiptPending
	}
	receipt := canonicalEVMReceipt{
		TransactionHash:   wire.TransactionHash,
		BlockHash:         wire.BlockHash,
		BlockNumber:       wire.BlockNumber,
		Status:            wire.Status,
		GasUsed:           wire.GasUsed,
		CumulativeGasUsed: wire.CumulativeGasUsed,
		ContractAddress:   wire.ContractAddress,
		Logs:              wire.Logs,
	}
	if !equalHex32(receipt.TransactionHash, txHash) || !validHex32(receipt.BlockHash) {
		return receipt, errors.New("invalid transaction receipt identity")
	}
	return receipt, nil
}

func (c *evmRPCClient) requireSuccessfulReceipt(ctx context.Context, txHash string) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		receipt, err := c.transactionReceipt(ctx, txHash)
		if err == nil {
			if strings.ToLower(receipt.Status) != "0x1" {
				return fmt.Errorf("receipt status %q", receipt.Status)
			}
			return nil
		}
		if !errors.Is(err, errEVMReceiptPending) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("transaction receipt timeout")
		case <-ticker.C:
		}
	}
}

func (c *evmRPCClient) transactionReceiptDigest(ctx context.Context, txHash string) (string, error) {
	receipt, err := c.transactionReceipt(ctx, txHash)
	if err != nil {
		return "", err
	}
	if strings.ToLower(receipt.Status) != "0x1" {
		return "", fmt.Errorf("receipt status %q", receipt.Status)
	}
	receipt.TransactionHash = normalizeHex32(receipt.TransactionHash)
	receipt.BlockHash = normalizeHex32(receipt.BlockHash)
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
