package executionproof

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
)

const (
	ReasonForkExecutionRequired ReasonCode = "EP-010-FORK-EXECUTION-REQUIRED"
	ReasonForkPayloadMismatch   ReasonCode = "EP-011-FORK-PAYLOAD-MISMATCH"
	ReasonForkReceiptMismatch   ReasonCode = "EP-012-FORK-RECEIPT-MISMATCH"
)

// VerifyForkAndForwardSafeTransaction is the v0.3 production boundary. It does
// not accept a caller-supplied simulation receipt. The verified fork is run
// inside the same fail-closed control path immediately before the existing
// native Safe hash gate and the side-effecting forwarder.
func VerifyForkAndForwardSafeTransaction(
	ctx context.Context,
	proof Proof,
	forkRequest VerifiedForkRequest,
	backend VerifiedForkBackend,
	req SafeForwardRequest,
	forwarder SafeForwarder,
) (SigningGateResult, VerifiedForkReceipt, error) {
	if backend == nil || forwarder == nil {
		return blockedForkSigning(ReasonForkExecutionRequired), VerifiedForkReceipt{}, ErrSigningBlocked
	}
	prepared, ok := prepareVerifiedForkRequest(forkRequest)
	if !ok || !safeTransactionMatchesFork(req.Transaction, prepared) {
		return blockedForkSigning(ReasonForkPayloadMismatch), VerifiedForkReceipt{}, ErrSigningBlocked
	}

	forkReceipt, err := RunVerifiedForkExecution(ctx, forkRequest, backend)
	if err != nil || !ValidVerifiedForkReceipt(forkReceipt) {
		return blockedForkSigning(ReasonForkExecutionRequired), forkReceipt, ErrSigningBlocked
	}
	if !forkReceiptMatchesProof(proof, forkReceipt, prepared) {
		return blockedForkSigning(ReasonForkReceiptMismatch), forkReceipt, ErrSigningBlocked
	}

	decision, err := VerifyAndForwardSafeTransaction(ctx, proof, req, forwarder)
	return decision, forkReceipt, err
}

func blockedForkSigning(reason ReasonCode) SigningGateResult {
	return SigningGateResult{Decision: DecisionBlock, Reasons: []ReasonCode{reason}}
}

func safeTransactionMatchesFork(tx SafeTransaction, prepared PreparedVerifiedForkRequest) bool {
	if !validSafeTransaction(tx) || prepared.Simulation.ChainID != tx.ChainID {
		return false
	}
	payload := prepared.Payload
	if !equalAddress(payload.From, tx.Safe) || !equalAddress(payload.To, tx.To) {
		return false
	}
	value, ok := parseHexUint256(payload.ValueHex)
	if !ok || value.Cmp(tx.Value) != 0 {
		return false
	}
	data, err := decodeCanonicalHexBytes(payload.DataHex)
	if err != nil || !equalBytes(data, tx.Data) {
		return false
	}
	return true
}

func forkReceiptMatchesProof(proof Proof, receipt VerifiedForkReceipt, prepared PreparedVerifiedForkRequest) bool {
	if proof.Evaluation.Decision != DecisionAllow || !ValidVerifiedForkReceipt(receipt) {
		return false
	}
	if proof.Envelope.Payload.ChainID != prepared.Simulation.ChainID || !strings.EqualFold(strings.TrimSpace(proof.Envelope.Payload.Target), strings.TrimSpace(prepared.Payload.To)) {
		return false
	}
	data, err := decodeCanonicalHexBytes(prepared.Payload.DataHex)
	if err != nil {
		return false
	}
	calldataDigest := sha256Hex(data)
	if !equalDigest(proof.Envelope.Payload.GeneratedCalldataSHA256, calldataDigest) || !equalDigest(proof.Envelope.Payload.ApprovedCalldataSHA256, calldataDigest) {
		return false
	}
	if !equalDigest(proof.Envelope.Simulation.InvariantSetSHA256, receipt.Simulation.InvariantSetSHA256) {
		return false
	}
	if !equalDigest(receipt.Simulation.PayloadSHA256, prepared.Simulation.PayloadSHA256) || receipt.Simulation.ChainID != prepared.Simulation.ChainID {
		return false
	}
	return true
}

func equalAddress(a, b string) bool {
	return strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(a), "0x"), strings.TrimPrefix(strings.TrimSpace(b), "0x"))
}

func parseHexUint256(value string) (*big.Int, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if value == "" { value = "0" }
	v := new(big.Int)
	if _, ok := v.SetString(value, 16); !ok || v.Sign() < 0 || v.BitLen() > 256 {
		return nil, false
	}
	return v, true
}

func decodeCanonicalHexBytes(value string) ([]byte, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if len(value)%2 != 0 { value = "0" + value }
	return hex.DecodeString(value)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) { return false }
	var diff byte
	for i := range a { diff |= a[i] ^ b[i] }
	return diff == 0
}

func sha256Hex(input []byte) string {
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:])
}
