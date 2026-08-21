package executionproof

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

var (
	safeDomainSeparatorTypeHash = mustHex32("47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218")
	safeTxTypeHash              = mustHex32("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8")
)

// NativeSafeTxHashComputer reproduces Safe v1.3+ getTransactionHash semantics:
// keccak256(0x1901 || domainSeparator(chainId, Safe) || SafeTx struct hash).
// It is intentionally independent of Safe Transaction Service responses.
type NativeSafeTxHashComputer struct{}

func (NativeSafeTxHashComputer) ComputeSafeTxHash(tx SafeTransaction) (string, error) {
	if !validSafeTransaction(tx) {
		return "", fmt.Errorf("invalid Safe transaction")
	}

	domain := make([]byte, 0, 96)
	domain = append(domain, safeDomainSeparatorTypeHash[:]...)
	chainWord, err := uintWord(new(big.Int).SetUint64(tx.ChainID))
	if err != nil {
		return "", err
	}
	domain = append(domain, chainWord[:]...)
	safeWord, err := addressWord(tx.Safe)
	if err != nil {
		return "", err
	}
	domain = append(domain, safeWord[:]...)
	domainHash := keccak256(domain)

	dataHash := keccak256(tx.Data)
	structData := make([]byte, 0, 352)
	structData = append(structData, safeTxTypeHash[:]...)
	toWord, err := addressWord(tx.To)
	if err != nil {
		return "", err
	}
	structData = append(structData, toWord[:]...)

	for _, value := range []*big.Int{
		tx.Value,
		new(big.Int).SetBytes(dataHash[:]),
		new(big.Int).SetUint64(uint64(tx.Operation)),
		tx.SafeTxGas,
		tx.BaseGas,
		tx.GasPrice,
	} {
		word, err := uintWord(value)
		if err != nil {
			return "", err
		}
		structData = append(structData, word[:]...)
	}

	gasTokenWord, err := addressWord(tx.GasToken)
	if err != nil {
		return "", err
	}
	structData = append(structData, gasTokenWord[:]...)
	refundWord, err := addressWord(tx.RefundReceiver)
	if err != nil {
		return "", err
	}
	structData = append(structData, refundWord[:]...)
	nonceWord, err := uintWord(tx.Nonce)
	if err != nil {
		return "", err
	}
	structData = append(structData, nonceWord[:]...)

	if len(structData) != 352 {
		return "", fmt.Errorf("unexpected SafeTx encoding length: %d", len(structData))
	}
	structHash := keccak256(structData)

	preimage := make([]byte, 0, 66)
	preimage = append(preimage, 0x19, 0x01)
	preimage = append(preimage, domainHash[:]...)
	preimage = append(preimage, structHash[:]...)
	result := keccak256(preimage)
	return "0x" + hex.EncodeToString(result[:]), nil
}

func keccak256(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func addressWord(v string) ([32]byte, error) {
	var out [32]byte
	raw := strings.TrimPrefix(strings.TrimSpace(v), "0x")
	if len(raw) != 40 {
		return out, fmt.Errorf("invalid address length")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return out, fmt.Errorf("decode address: %w", err)
	}
	copy(out[12:], decoded)
	return out, nil
}

func uintWord(v *big.Int) ([32]byte, error) {
	var out [32]byte
	if v == nil || v.Sign() < 0 || v.BitLen() > 256 {
		return out, fmt.Errorf("value outside uint256")
	}
	b := v.Bytes()
	copy(out[32-len(b):], b)
	return out, nil
}

func mustHex32(v string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != 32 {
		panic("invalid 32-byte constant")
	}
	copy(out[:], b)
	return out
}
