package executionproof

import (
	"bytes"
	"math/big"
	"testing"
)

func TestCanonicalSafeActionArtifactDeterministicRoundTrip(t *testing.T) {
	req := validSafeForwardRequest()
	first, err := CanonicalSafeActionArtifact(req.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalSafeActionArtifact(req.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	if first.Kind != SafeActionArtifactKind || !bytes.Equal(first.Canonical, second.Canonical) || first.SHA256() != second.SHA256() {
		t.Fatal("canonical Safe action is not deterministic")
	}

	decoded, err := decodeCanonicalSafeAction(first)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := CanonicalSafeActionArtifact(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Canonical, roundTrip.Canonical) {
		t.Fatal("Safe action round-trip changed canonical bytes")
	}
}

func TestCanonicalSafeActionIdentityChangesForNonCalldataFields(t *testing.T) {
	baseReq := validSafeForwardRequest()
	base, err := CanonicalSafeActionArtifact(baseReq.Transaction)
	if err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name string
		mut  func(*SafeTransaction)
	}{
		{"value", func(tx *SafeTransaction) { tx.Value = new(big.Int).Add(tx.Value, big.NewInt(1)) }},
		{"operation", func(tx *SafeTransaction) { tx.Operation = 1 }},
		{"nonce", func(tx *SafeTransaction) { tx.Nonce = new(big.Int).Add(tx.Nonce, big.NewInt(1)) }},
		{"safeTxGas", func(tx *SafeTransaction) { tx.SafeTxGas = new(big.Int).Add(tx.SafeTxGas, big.NewInt(1)) }},
		{"refundReceiver", func(tx *SafeTransaction) { tx.RefundReceiver = "0x9999999999999999999999999999999999999999" }},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			tx := baseReq.Transaction
			tc.mut(&tx)
			artifact, err := CanonicalSafeActionArtifact(tx)
			if err != nil {
				t.Fatal(err)
			}
			if artifact.SHA256() == base.SHA256() {
				t.Fatalf("%s mutation did not change full action identity", tc.name)
			}
		})
	}
}

func TestDecodeCanonicalSafeActionRejectsNonCanonicalEncoding(t *testing.T) {
	req := validSafeForwardRequest()
	artifact, err := CanonicalSafeActionArtifact(req.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Canonical = append([]byte(" "), artifact.Canonical...)
	if _, err := decodeCanonicalSafeAction(artifact); err == nil {
		t.Fatal("non-canonical Safe action encoding accepted")
	}
}
