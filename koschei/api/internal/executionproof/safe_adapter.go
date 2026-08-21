package executionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
)

// SafeTransaction contains every field that participates in Safe's
// getTransactionHash calculation. Nothing supplied by a Transaction Service is
// omitted from the authorization boundary.
type SafeTransaction struct {
	ChainID        uint64
	Safe           string
	To             string
	Value          *big.Int
	Data           []byte
	Operation      uint8
	SafeTxGas      *big.Int
	BaseGas        *big.Int
	GasPrice       *big.Int
	GasToken       string
	RefundReceiver string
	Nonce          *big.Int
}

// SafeTxHashComputer is deliberately narrow. Production implementations must
// derive the hash from SafeTransaction using Safe getTransactionHash semantics
// (EIP-712 domain: chain ID + Safe address). A Transaction Service response is
// never a valid implementation of this interface by itself.
type SafeTxHashComputer interface {
	ComputeSafeTxHash(tx SafeTransaction) (string, error)
}

type SafeForwardRequest struct {
	Transaction       SafeTransaction
	PresentedSafeHash string
}

const ReasonSafeHashMismatch ReasonCode = "EP-009-SAFE-HASH-MISMATCH"

// AuthorizeSafeForward is the concrete Safe adapter boundary. It validates the
// complete raw transaction, independently derives safeTxHash, rejects a service
// hash mismatch, then delegates to the deterministic Execution Proof gate.
func AuthorizeSafeForward(proof Proof, req SafeForwardRequest, computer SafeTxHashComputer) SigningGateResult {
	if computer == nil || !validSafeTransaction(req.Transaction) || !validHex32(req.PresentedSafeHash) {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}
	}

	computed, err := computer.ComputeSafeTxHash(req.Transaction)
	if err != nil || !validHex32(computed) {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidSigningRequest}}
	}
	if !equalHex32(computed, req.PresentedSafeHash) {
		return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonSafeHashMismatch}}
	}

	calldataDigest := sha256.Sum256(req.Transaction.Data)
	return AuthorizeSigningRequest(proof, SigningRequest{
		ChainID:        req.Transaction.ChainID,
		Target:         req.Transaction.To,
		CalldataSHA256: hex.EncodeToString(calldataDigest[:]),
		SafeTxHash:     computed,
	})
}

func validSafeTransaction(tx SafeTransaction) bool {
	return tx.ChainID != 0 &&
		validAddress(tx.Safe) && validAddress(tx.To) &&
		validUint256(tx.Value) &&
		tx.Operation <= 1 &&
		validUint256(tx.SafeTxGas) &&
		validUint256(tx.BaseGas) &&
		validUint256(tx.GasPrice) &&
		validAddress(tx.GasToken) && validAddress(tx.RefundReceiver) &&
		validUint256(tx.Nonce)
}

func validUint256(v *big.Int) bool {
	return v != nil && v.Sign() >= 0 && v.BitLen() <= 256
}

func validAddress(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "0x")
	if len(v) != 40 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
