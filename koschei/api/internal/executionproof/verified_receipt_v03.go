package executionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const VerifiedForkReceiptVersion = "koschei-verified-fork-receipt/v0.3"

const (
	SimulationExecutionEvidenceInvalid SimulationReason = "SIM-013-EXECUTION-EVIDENCE-INVALID"
	SimulationReceiptBindingMismatch   SimulationReason = "SIM-014-RECEIPT-BINDING-MISMATCH"
)

// ForkExecutionEvidence binds the isolated execution itself to the invariant
// receipt. The transaction receipt digest is produced from a canonical subset
// of the EVM receipt, while InvariantEvidenceSHA256 is independently derived
// from the canonicalized invariant checks.
type ForkExecutionEvidence struct {
	TransactionHash        string `json:"transaction_hash"`
	TransactionReceiptSHA256 string `json:"transaction_receipt_sha256"`
	InvariantEvidenceSHA256 string `json:"invariant_evidence_sha256"`
}

// VerifiedForkReceipt is the v0.3 artifact that may be bound into a signing
// authorization. It wraps the deterministic v0.2 simulation receipt and exact
// isolated-execution evidence under one digest.
type VerifiedForkReceipt struct {
	Version      string                `json:"version"`
	Simulation   ForkSimulationReceipt `json:"simulation"`
	Execution    ForkExecutionEvidence `json:"execution"`
	ReceiptSHA256 string               `json:"receipt_sha256"`
}

func canonicalInvariantEvidenceDigest(checks []InvariantCheck) string {
	canonical, _ := canonicalizeInvariantChecks(checks)
	encoded, err := json.Marshal(canonical)
	if err != nil {
		panic("InvariantCheck must remain JSON serializable")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validForkExecutionEvidence(e ForkExecutionEvidence, checks []InvariantCheck) bool {
	return validHex32(e.TransactionHash) &&
		validSHA256(e.TransactionReceiptSHA256) &&
		validSHA256(e.InvariantEvidenceSHA256) &&
		equalDigest(e.InvariantEvidenceSHA256, canonicalInvariantEvidenceDigest(checks))
}

func verifiedForkReceiptDigest(receipt VerifiedForkReceipt) string {
	copyReceipt := receipt
	copyReceipt.ReceiptSHA256 = ""
	copyReceipt.Execution.TransactionHash = normalizeHex32(copyReceipt.Execution.TransactionHash)
	copyReceipt.Execution.TransactionReceiptSHA256 = strings.ToLower(strings.TrimSpace(copyReceipt.Execution.TransactionReceiptSHA256))
	copyReceipt.Execution.InvariantEvidenceSHA256 = strings.ToLower(strings.TrimSpace(copyReceipt.Execution.InvariantEvidenceSHA256))
	encoded, err := json.Marshal(copyReceipt)
	if err != nil {
		panic("VerifiedForkReceipt must remain JSON serializable")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func ValidVerifiedForkReceipt(receipt VerifiedForkReceipt) bool {
	if receipt.Version != VerifiedForkReceiptVersion || receipt.Simulation.Decision != SimulationAllow {
		return false
	}
	if receipt.Simulation.ReceiptSHA256 != simulationReceiptDigest(receipt.Simulation) {
		return false
	}
	if !validForkExecutionEvidence(receipt.Execution, receipt.Simulation.Checks) {
		return false
	}
	return equalDigest(receipt.ReceiptSHA256, verifiedForkReceiptDigest(receipt))
}
