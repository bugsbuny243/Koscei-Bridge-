package executionproof

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"koschei/api/internal/executioncontainment"
)

const SafeActionArtifactKind = "safe-transaction/v1"

type canonicalSafeAction struct {
	ChainID        uint64 `json:"chain_id"`
	Safe           string `json:"safe"`
	To             string `json:"to"`
	Value          string `json:"value"`
	DataHex        string `json:"data_hex"`
	Operation      uint8  `json:"operation"`
	SafeTxGas      string `json:"safe_tx_gas"`
	BaseGas        string `json:"base_gas"`
	GasPrice       string `json:"gas_price"`
	GasToken       string `json:"gas_token"`
	RefundReceiver string `json:"refund_receiver"`
	Nonce          string `json:"nonce"`
}

// CanonicalSafeActionArtifact returns the exact full Safe action material bound
// into containment. This is deliberately stronger than calldata-only identity:
// value, operation, nonce, gas/refund fields and Safe address all participate.
func CanonicalSafeActionArtifact(tx SafeTransaction) (executioncontainment.ActionArtifact, error) {
	if !validSafeTransaction(tx) {
		return executioncontainment.ActionArtifact{}, fmt.Errorf("invalid Safe transaction")
	}

	wire := canonicalSafeAction{
		ChainID:        tx.ChainID,
		Safe:           normalizeAddress(tx.Safe),
		To:             normalizeAddress(tx.To),
		Value:          tx.Value.String(),
		DataHex:        "0x" + hex.EncodeToString(tx.Data),
		Operation:      tx.Operation,
		SafeTxGas:      tx.SafeTxGas.String(),
		BaseGas:        tx.BaseGas.String(),
		GasPrice:       tx.GasPrice.String(),
		GasToken:       normalizeAddress(tx.GasToken),
		RefundReceiver: normalizeAddress(tx.RefundReceiver),
		Nonce:          tx.Nonce.String(),
	}

	encoded, err := json.Marshal(wire)
	if err != nil {
		return executioncontainment.ActionArtifact{}, fmt.Errorf("marshal canonical Safe action: %w", err)
	}
	return executioncontainment.ActionArtifact{Kind: SafeActionArtifactKind, Canonical: encoded}, nil
}

func decodeCanonicalSafeAction(action executioncontainment.ActionArtifact) (SafeTransaction, error) {
	if action.Kind != SafeActionArtifactKind || len(action.Canonical) == 0 {
		return SafeTransaction{}, fmt.Errorf("unsupported Safe action artifact")
	}

	var wire canonicalSafeAction
	if err := json.Unmarshal(action.Canonical, &wire); err != nil {
		return SafeTransaction{}, fmt.Errorf("decode canonical Safe action: %w", err)
	}
	dataRaw := strings.TrimPrefix(strings.TrimSpace(wire.DataHex), "0x")
	data, err := hex.DecodeString(dataRaw)
	if err != nil {
		return SafeTransaction{}, fmt.Errorf("decode Safe calldata: %w", err)
	}

	tx := SafeTransaction{
		ChainID:        wire.ChainID,
		Safe:           wire.Safe,
		To:             wire.To,
		Value:          parseUint256Decimal(wire.Value),
		Data:           data,
		Operation:      wire.Operation,
		SafeTxGas:      parseUint256Decimal(wire.SafeTxGas),
		BaseGas:        parseUint256Decimal(wire.BaseGas),
		GasPrice:       parseUint256Decimal(wire.GasPrice),
		GasToken:       wire.GasToken,
		RefundReceiver: wire.RefundReceiver,
		Nonce:          parseUint256Decimal(wire.Nonce),
	}
	if !validSafeTransaction(tx) {
		return SafeTransaction{}, fmt.Errorf("decoded Safe action is invalid")
	}

	// Reject non-canonical aliases/encodings by requiring byte-identical
	// round-trip encoding. The runner therefore cannot accept semantically
	// equivalent but differently encoded action material under one digest.
	reencoded, err := CanonicalSafeActionArtifact(tx)
	if err != nil || string(reencoded.Canonical) != string(action.Canonical) {
		return SafeTransaction{}, fmt.Errorf("non-canonical Safe action encoding")
	}
	return tx, nil
}

func parseUint256Decimal(value string) *big.Int {
	v, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil
	}
	return v
}

func normalizeAddress(value string) string {
	return "0x" + strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "0x"))
}
