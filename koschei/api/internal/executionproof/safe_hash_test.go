package executionproof

import (
	"math/big"
	"testing"
)

// These schema strings are pinned to safe-fndn/safe-smart-account
// commit 37a8215a8f2a10e275650cfce0059dbfb480030e, specifically
// contracts/Safe.sol and src/utils/execution.ts. Keeping the schema itself
// under test prevents silent field-order or field-type drift even if a
// downstream golden transaction hash were accidentally updated.
func TestSafeEIP712TypeHashesMatchPinnedUpstreamSchema(t *testing.T) {
	domain := keccak256([]byte("EIP712Domain(uint256 chainId,address verifyingContract)"))
	if domain != safeDomainSeparatorTypeHash {
		t.Fatalf("Safe domain typehash drifted: got %x want %x", domain, safeDomainSeparatorTypeHash)
	}

	safeTx := keccak256([]byte("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"))
	if safeTx != safeTxTypeHash {
		t.Fatalf("SafeTx typehash drifted: got %x want %x", safeTx, safeTxTypeHash)
	}
}

func TestNativeSafeTxHashComputerMatchesReferenceVector(t *testing.T) {
	tx := SafeTransaction{
		ChainID:        1,
		Safe:           "0x1111111111111111111111111111111111111111",
		To:             "0x2222222222222222222222222222222222222222",
		Value:          big.NewInt(123),
		Data:           []byte{0xde, 0xad, 0xbe, 0xef},
		Operation:      0,
		SafeTxGas:      big.NewInt(50000),
		BaseGas:        big.NewInt(21000),
		GasPrice:       big.NewInt(1000000000),
		GasToken:       "0x0000000000000000000000000000000000000000",
		RefundReceiver: "0x3333333333333333333333333333333333333333",
		Nonce:          big.NewInt(7),
	}

	got, err := (NativeSafeTxHashComputer{}).ComputeSafeTxHash(tx)
	if err != nil {
		t.Fatal(err)
	}
	const want = "0xe05fbc07825f1ce3b990ad97a59f8b7be66684b1edae847b86c63d9e677eec3b"
	if got != want {
		t.Fatalf("safeTxHash = %s, want %s", got, want)
	}
}

func TestNativeSafeTxHashComputerBindsDomainChainID(t *testing.T) {
	tx := validSafeForwardRequest().Transaction
	first, err := (NativeSafeTxHashComputer{}).ComputeSafeTxHash(tx)
	if err != nil {
		t.Fatal(err)
	}
	tx.ChainID++
	second, err := (NativeSafeTxHashComputer{}).ComputeSafeTxHash(tx)
	if err != nil {
		t.Fatal(err)
	}
	if equalHex32(first, second) {
		t.Fatal("safeTxHash did not change when chain ID changed")
	}
}

func TestNativeSafeTxHashComputerRejectsUint256Overflow(t *testing.T) {
	tx := validSafeForwardRequest().Transaction
	tx.Value = new(big.Int).Lsh(big.NewInt(1), 256)
	if _, err := (NativeSafeTxHashComputer{}).ComputeSafeTxHash(tx); err == nil {
		t.Fatal("expected uint256 overflow to fail")
	}
}
