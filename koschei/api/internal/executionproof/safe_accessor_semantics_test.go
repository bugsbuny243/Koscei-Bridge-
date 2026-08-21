package executionproof

import (
	"math/big"
	"testing"
)

const testSafeAccessor = "0x4444444444444444444444444444444444444444"

func validSafeAccessorTraceFixture(t *testing.T, tx SafeTransaction, accessor string) SafeTraceEvidence {
	t.Helper()
	inputSHA, ok := safeAccessorSimulateCalldataSHA256(tx)
	if !ok {
		t.Fatal("failed to encode accessor simulate calldata")
	}
	kind := "call"
	if tx.Operation == 1 {
		kind = "delegatecall"
	}
	trace := SafeTraceEvidence{
		RootSafe: tx.Safe,
		Frames: []SafeTraceFrame{
			{Depth: 0, Type: "delegatecall", From: tx.Safe, To: accessor, InputSHA256: inputSHA, Value: "0", Success: true},
			{Depth: 1, Type: kind, From: tx.Safe, To: tx.To, InputSHA256: "abababababababababababababababababababababababababababababababab", Value: tx.Value.String(), Success: true},
		},
	}
	trace.TraceSHA256 = safeTraceDigest(trace)
	return trace
}

func TestSafeAccessorSemanticsVerifierAcceptsBoundAccessorPath(t *testing.T) {
	tx := validSafeForwardRequest().Transaction
	trace := validSafeAccessorTraceFixture(t, tx, testSafeAccessor)
	if !(SafeAccessorSemanticsVerifier{Accessor: testSafeAccessor}).Verify(tx, trace) {
		t.Fatal("valid Safe accessor path rejected")
	}
}

func TestSafeAccessorSemanticsVerifierRejectsGenericDirectCall(t *testing.T) {
	tx := validSafeForwardRequest().Transaction
	trace := validSafeTraceFixture(tx.Safe, tx.To)
	if (SafeAccessorSemanticsVerifier{Accessor: testSafeAccessor}).Verify(tx, trace) {
		t.Fatal("generic direct call must not satisfy Safe semantics")
	}
}

func TestSafeAccessorSemanticsVerifierRejectsWrongAccessor(t *testing.T) {
	tx := validSafeForwardRequest().Transaction
	trace := validSafeAccessorTraceFixture(t, tx, testSafeAccessor)
	if (SafeAccessorSemanticsVerifier{Accessor: "0x5555555555555555555555555555555555555555"}).Verify(tx, trace) {
		t.Fatal("wrong accessor identity accepted")
	}
}

func TestSafeAccessorSemanticsVerifierRejectsMutatedTransaction(t *testing.T) {
	tx := validSafeForwardRequest().Transaction
	trace := validSafeAccessorTraceFixture(t, tx, testSafeAccessor)
	tx.Value = big.NewInt(1)
	if (SafeAccessorSemanticsVerifier{Accessor: testSafeAccessor}).Verify(tx, trace) {
		t.Fatal("trace for another Safe transaction accepted")
	}
}

func TestSafeAccessorCalldataDigestChangesWithOperation(t *testing.T) {
	tx := validSafeForwardRequest().Transaction
	first, ok := safeAccessorSimulateCalldataSHA256(tx)
	if !ok {
		t.Fatal("encode call transaction")
	}
	tx.Operation = 1
	second, ok := safeAccessorSimulateCalldataSHA256(tx)
	if !ok {
		t.Fatal("encode delegatecall transaction")
	}
	if first == second {
		t.Fatal("operation mutation did not change accessor calldata identity")
	}
}
