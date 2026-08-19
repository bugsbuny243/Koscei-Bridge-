package executionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const VerifiedForkReceiptVersion = "koschei-verified-fork-receipt/v0.3"

const (
	ExecutionModelEVMDirectCallV03 = "evm-direct-call/v0.3"
	ExecutionModelSafeSimulateTxV1 = "safe-simulate-tx-accessor/v1"

	SimulationExecutionEvidenceInvalid SimulationReason = "SIM-013-EXECUTION-EVIDENCE-INVALID"
	SimulationReceiptBindingMismatch   SimulationReason = "SIM-014-RECEIPT-BINDING-MISMATCH"
)

// ForkExecutionEvidence binds the isolated execution itself to the invariant
// receipt. ExecutionModel prevents evidence produced under one EVM semantic
// model from being reused as if it proved a stronger model (for example a
// direct call being presented as Safe execTransaction semantics).
type ForkExecutionEvidence struct {
	ExecutionModel           string `json:"execution_model"`
	TransactionHash          string `json:"transaction_hash"`
	TransactionReceiptSHA256 string `json:"transaction_receipt_sha256"`
	InvariantEvidenceSHA256  string `json:"invariant_evidence_sha256"`
}

// VerifiedForkReceipt is the v0.3 artifact that may be bound into an
// authorization. It wraps the deterministic v0.2 simulation receipt and exact
// isolated-execution evidence under one digest.
type VerifiedForkReceipt struct {
	Version       string                `json:"version"`
	Simulation    ForkSimulationReceipt `json:"simulation"`
	Execution     ForkExecutionEvidence `json:"execution"`
	ReceiptSHA256 string                `json:"receipt_sha256"`
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

// canonicalExecutionModel deliberately maps an omitted model to the weakest
// supported semantics. Legacy/generic backends can therefore remain usable as
// direct-call evidence, but omission can never upgrade evidence into Safe-aware
// execution semantics.
func canonicalExecutionModel(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ExecutionModelEVMDirectCallV03
	}
	return model
}

func validExecutionModel(model string) bool {
	switch canonicalExecutionModel(model) {
	case ExecutionModelEVMDirectCallV03, ExecutionModelSafeSimulateTxV1:
		return true
	default:
		return false
	}
}

func validForkExecutionEvidence(e ForkExecutionEvidence, checks []InvariantCheck) bool {
	return validExecutionModel(e.ExecutionModel) &&
		validHex32(e.TransactionHash) &&
		validSHA256(e.TransactionReceiptSHA256) &&
		validSHA256(e.InvariantEvidenceSHA256) &&
		equalDigest(e.InvariantEvidenceSHA256, canonicalInvariantEvidenceDigest(checks))
}

func verifiedForkReceiptDigest(receipt VerifiedForkReceipt) string {
	copyReceipt := receipt
	copyReceipt.ReceiptSHA256 = ""
	copyReceipt.Execution.ExecutionModel = canonicalExecutionModel(copyReceipt.Execution.ExecutionModel)
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
