package executionproof

import (
	"errors"
	"math/big"
	"strings"
	"testing"
)

type fixedSafeHashComputer struct {
	hash string
	err  error
}

func (f fixedSafeHashComputer) ComputeSafeTxHash(SafeTransaction) (string, error) {
	return f.hash, f.err
}

func validSafeForwardRequest() SafeForwardRequest {
	return SafeForwardRequest{
		Transaction: SafeTransaction{
			ChainID:        1,
			Safe:           "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			To:             "0x1111111111111111111111111111111111111111",
			Value:          big.NewInt(0),
			Data:           nil,
			Operation:      0,
			SafeTxGas:      big.NewInt(0),
			BaseGas:        big.NewInt(0),
			GasPrice:       big.NewInt(0),
			GasToken:       "0x0000000000000000000000000000000000000000",
			RefundReceiver: "0x0000000000000000000000000000000000000000",
			Nonce:          big.NewInt(7),
		},
		PresentedSafeHash: "0x" + strings.Repeat("4", 64),
	}
}

func proofForSafeForward(t *testing.T, req SafeForwardRequest) Proof {
	t.Helper()
	e := validEnvelope()
	e.Payload.ChainID = req.Transaction.ChainID
	e.Payload.Target = req.Transaction.To
	// sha256(nil)
	e.Payload.ApprovedCalldataSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	e.Payload.GeneratedCalldataSHA256 = e.Payload.ApprovedCalldataSHA256
	e.Authorization.ApprovedSigningRequestID = req.PresentedSafeHash
	proof, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestAuthorizeSafeForwardAllowsOnlyRecomputedMatchingHash(t *testing.T) {
	req := validSafeForwardRequest()
	proof := proofForSafeForward(t, req)
	got := AuthorizeSafeForward(proof, req, fixedSafeHashComputer{hash: req.PresentedSafeHash})
	if got.Decision != DecisionAllow {
		t.Fatalf("decision = %s, reasons = %v", got.Decision, got.Reasons)
	}
}

func TestAuthorizeSafeForwardBlocksTransactionServiceHashMismatch(t *testing.T) {
	req := validSafeForwardRequest()
	proof := proofForSafeForward(t, req)
	got := AuthorizeSafeForward(proof, req, fixedSafeHashComputer{hash: "0x" + strings.Repeat("5", 64)})
	assertSigningBlockedFor(t, got, ReasonSafeHashMismatch)
}

func TestAuthorizeSafeForwardBlocksHashComputationFailure(t *testing.T) {
	req := validSafeForwardRequest()
	proof := proofForSafeForward(t, req)
	got := AuthorizeSafeForward(proof, req, fixedSafeHashComputer{err: errors.New("hash unavailable")})
	assertSigningBlockedFor(t, got, ReasonInvalidSigningRequest)
}

func TestAuthorizeSafeForwardBlocksInvalidRawSafeFields(t *testing.T) {
	req := validSafeForwardRequest()
	proof := proofForSafeForward(t, req)
	req.Transaction.Operation = 2
	got := AuthorizeSafeForward(proof, req, fixedSafeHashComputer{hash: req.PresentedSafeHash})
	assertSigningBlockedFor(t, got, ReasonInvalidSigningRequest)
}

func TestAuthorizeSafeForwardBlocksProofBoundToDifferentSafeHash(t *testing.T) {
	req := validSafeForwardRequest()
	proof := proofForSafeForward(t, req)
	proof.Envelope.Authorization.ApprovedSigningRequestID = "0x" + strings.Repeat("6", 64)
	// Re-evaluate so this specifically exercises request identity rather than proof tamper detection.
	proof, _ = Evaluate(proof.Envelope)
	got := AuthorizeSafeForward(proof, req, fixedSafeHashComputer{hash: req.PresentedSafeHash})
	assertSigningBlockedFor(t, got, ReasonSigningRequestMismatch)
}
