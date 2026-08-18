package executionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
)

// SafeAccessorSemanticsVerifier proves that isolated execution actually entered
// through Safe's StorageAccessible -> SimulateTxAccessor delegatecall path.
// A generic direct call from an impersonated Safe address is not sufficient.
type SafeAccessorSemanticsVerifier struct {
	Accessor string
}

func (v SafeAccessorSemanticsVerifier) Verify(tx SafeTransaction, trace SafeTraceEvidence) bool {
	if !validSafeTransaction(tx) || !validAddress(v.Accessor) || !(SafeTraceVerifier{}).Verify(trace) {
		return false
	}
	if normalizeAddress(trace.RootSafe) != normalizeAddress(tx.Safe) || len(trace.Frames) < 2 {
		return false
	}

	expectedInput, ok := safeAccessorSimulateCalldataSHA256(tx)
	if !ok {
		return false
	}
	entry := trace.Frames[0]
	if entry.Depth != 0 || strings.ToLower(strings.TrimSpace(entry.Type)) != "delegatecall" ||
		normalizeAddress(entry.From) != normalizeAddress(tx.Safe) ||
		normalizeAddress(entry.To) != normalizeAddress(v.Accessor) ||
		!strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(entry.InputSHA256), "0x"), expectedInput) || !entry.Success {
		return false
	}

	exec := trace.Frames[1]
	expectedKind := "call"
	if tx.Operation == 1 {
		expectedKind = "delegatecall"
	}
	if exec.Depth != 1 || strings.ToLower(strings.TrimSpace(exec.Type)) != expectedKind ||
		normalizeAddress(exec.From) != normalizeAddress(tx.Safe) ||
		normalizeAddress(exec.To) != normalizeAddress(tx.To) || !exec.Success {
		return false
	}
	amount, ok := new(big.Int).SetString(strings.TrimSpace(exec.Value), 10)
	if !ok || amount.Cmp(tx.Value) != 0 {
		return false
	}
	return true
}

// safeAccessorSimulateCalldataSHA256 returns SHA-256 of ABI calldata for
// SimulateTxAccessor.simulate(address,uint256,bytes,uint8). The selector is
// derived locally from the function signature; no RPC/service value is trusted.
func safeAccessorSimulateCalldataSHA256(tx SafeTransaction) (string, bool) {
	if !validSafeTransaction(tx) {
		return "", false
	}
	selectorHash := keccak256([]byte("simulate(address,uint256,bytes,uint8)"))
	toWord, err := addressWord(tx.To)
	if err != nil { return "", false }
	valueWord, err := uintWord(tx.Value)
	if err != nil { return "", false }
	offsetWord, err := uintWord(big.NewInt(128))
	if err != nil { return "", false }
	opWord, err := uintWord(new(big.Int).SetUint64(uint64(tx.Operation)))
	if err != nil { return "", false }
	lengthWord, err := uintWord(new(big.Int).SetUint64(uint64(len(tx.Data))))
	if err != nil { return "", false }

	padded := ((len(tx.Data) + 31) / 32) * 32
	calldata := make([]byte, 0, 4+32*5+padded)
	calldata = append(calldata, selectorHash[:4]...)
	calldata = append(calldata, toWord[:]...)
	calldata = append(calldata, valueWord[:]...)
	calldata = append(calldata, offsetWord[:]...)
	calldata = append(calldata, opWord[:]...)
	calldata = append(calldata, lengthWord[:]...)
	calldata = append(calldata, tx.Data...)
	calldata = append(calldata, make([]byte, padded-len(tx.Data))...)
	sum := sha256.Sum256(calldata)
	return hex.EncodeToString(sum[:]), true
}
