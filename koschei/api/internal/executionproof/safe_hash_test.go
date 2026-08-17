package executionproof

import (
	"math/big"
	"testing"
)

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
	tx := validRawSafeTransaction()
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
	tx := validRawSafeTransaction()
	tx.Value = new(big.Int).Lsh(big.NewInt(1), 256)
	if _, err := (NativeSafeTxHashComputer{}).ComputeSafeTxHash(tx); err == nil {
		t.Fatal("expected uint256 overflow to fail")
	}
}
