package handlers

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"koschei/api/internal/executionproof"
)

const safeExecutionAssuranceMaxDataBytes = 128 << 10

type safeExecutionAssuranceAPIRequest struct {
	ExecutionProof      executionproof.Proof                       `json:"execution_proof"`
	Transaction         safeExecutionAssuranceTransactionAPIInput  `json:"transaction"`
	PresentedSafeTxHash string                                     `json:"presented_safe_tx_hash"`
}

type safeExecutionAssuranceTransactionAPIInput struct {
	ChainID        uint64 `json:"chain_id"`
	Safe           string `json:"safe"`
	To             string `json:"to"`
	Value          string `json:"value"`
	Data           string `json:"data"`
	Operation      uint8  `json:"operation"`
	SafeTxGas      string `json:"safe_tx_gas"`
	BaseGas        string `json:"base_gas"`
	GasPrice       string `json:"gas_price"`
	GasToken       string `json:"gas_token"`
	RefundReceiver string `json:"refund_receiver"`
	Nonce          string `json:"nonce"`
}

type safeExecutionAssuranceAPIResponse struct {
	OK                            bool                        `json:"ok"`
	Product                       string                      `json:"product"`
	Decision                      executionproof.Decision     `json:"decision"`
	ReasonCodes                   []executionproof.ReasonCode `json:"reason_codes"`
	EvidenceModel                 string                      `json:"evidence_model"`
	ComputedSafeTxHash            string                      `json:"computed_safe_tx_hash"`
	PresentedSafeTxHash           string                      `json:"presented_safe_tx_hash"`
	PresentedEnvelopeSHA256       string                      `json:"presented_envelope_sha256"`
	RecomputedEnvelopeSHA256      string                      `json:"recomputed_envelope_sha256"`
	MainnetTransactionSent        bool                        `json:"mainnet_transaction_sent"`
	SigningAuthority              bool                        `json:"signing_authority"`
	ForwardingAuthority           bool                        `json:"forwarding_authority"`
	ProductionControlMutation     bool                        `json:"production_control_mutation"`
	Limitations                   []string                    `json:"limitations"`
}

// SafeExecutionAssuranceV1 is a read-only Safe signing verification boundary.
// It independently rebuilds safeTxHash from the complete raw Safe transaction,
// recomputes the Execution Proof from its envelope, and returns a deterministic
// ALLOW/BLOCK result for the exact signing request. It has no signing key,
// forwarder, mainnet submission path, or production mutation authority.
func (h *Handler) SafeExecutionAssuranceV1(w http.ResponseWriter, r *http.Request) {
	var input safeExecutionAssuranceAPIRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "invalid_request", "message": "Invalid Safe execution assurance request.",
		})
		return
	}

	tx, err := decodeSafeExecutionAssuranceTransaction(input.Transaction)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "invalid_safe_transaction", "message": err.Error(),
		})
		return
	}
	presentedSafeTxHash := strings.TrimSpace(input.PresentedSafeTxHash)
	if !validSafeExecutionAssuranceHex32(presentedSafeTxHash) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "invalid_safe_tx_hash", "message": "presented_safe_tx_hash must be a 32-byte hex value.",
		})
		return
	}

	computer := executionproof.NativeSafeTxHashComputer{}
	computedSafeTxHash, err := computer.ComputeSafeTxHash(tx)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "invalid_safe_transaction", "message": "Safe transaction fields are invalid.",
		})
		return
	}
	recomputedProof, err := executionproof.Evaluate(input.ExecutionProof.Envelope)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "invalid_execution_proof", "message": "Execution Proof envelope could not be recomputed.",
		})
		return
	}

	gate := executionproof.AuthorizeSafeForward(input.ExecutionProof, executionproof.SafeForwardRequest{
		Transaction:       tx,
		PresentedSafeHash: presentedSafeTxHash,
	}, computer)

	writeJSON(w, http.StatusOK, safeExecutionAssuranceAPIResponse{
		OK:                       true,
		Product:                  "Koschei Execution Assurance",
		Decision:                 gate.Decision,
		ReasonCodes:              gate.Reasons,
		EvidenceModel:            "recomputed_execution_proof_plus_native_safe_eip712_hash",
		ComputedSafeTxHash:       computedSafeTxHash,
		PresentedSafeTxHash:      presentedSafeTxHash,
		PresentedEnvelopeSHA256:  strings.TrimSpace(input.ExecutionProof.EnvelopeSHA256),
		RecomputedEnvelopeSHA256: recomputedProof.EnvelopeSHA256,
		MainnetTransactionSent:   false,
		SigningAuthority:         false,
		ForwardingAuthority:      false,
		ProductionControlMutation: false,
		Limitations: []string{
			"Verification applies only to the exact Execution Proof envelope and complete Safe transaction supplied in this request.",
			"This endpoint does not sign, forward, submit, replace, or execute a Safe transaction.",
		},
	})
}

func decodeSafeExecutionAssuranceTransaction(input safeExecutionAssuranceTransactionAPIInput) (executionproof.SafeTransaction, error) {
	value, err := parseSafeExecutionAssuranceUint256("value", input.Value)
	if err != nil {
		return executionproof.SafeTransaction{}, err
	}
	safeTxGas, err := parseSafeExecutionAssuranceUint256("safe_tx_gas", input.SafeTxGas)
	if err != nil {
		return executionproof.SafeTransaction{}, err
	}
	baseGas, err := parseSafeExecutionAssuranceUint256("base_gas", input.BaseGas)
	if err != nil {
		return executionproof.SafeTransaction{}, err
	}
	gasPrice, err := parseSafeExecutionAssuranceUint256("gas_price", input.GasPrice)
	if err != nil {
		return executionproof.SafeTransaction{}, err
	}
	nonce, err := parseSafeExecutionAssuranceUint256("nonce", input.Nonce)
	if err != nil {
		return executionproof.SafeTransaction{}, err
	}
	data, err := decodeSafeExecutionAssuranceCalldata(input.Data)
	if err != nil {
		return executionproof.SafeTransaction{}, err
	}

	return executionproof.SafeTransaction{
		ChainID:        input.ChainID,
		Safe:           strings.TrimSpace(input.Safe),
		To:             strings.TrimSpace(input.To),
		Value:          value,
		Data:           data,
		Operation:      input.Operation,
		SafeTxGas:      safeTxGas,
		BaseGas:        baseGas,
		GasPrice:       gasPrice,
		GasToken:       strings.TrimSpace(input.GasToken),
		RefundReceiver: strings.TrimSpace(input.RefundReceiver),
		Nonce:          nonce,
	}, nil
}

func parseSafeExecutionAssuranceUint256(field, raw string) (*big.Int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return nil, fmt.Errorf("%s must be an unsigned integer", field)
	}

	base := 10
	digits := value
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		digits = value[2:]
	}
	if digits == "" {
		return nil, fmt.Errorf("%s must contain digits", field)
	}
	parsed, ok := new(big.Int).SetString(digits, base)
	if !ok || parsed.Sign() < 0 || parsed.BitLen() > 256 {
		return nil, fmt.Errorf("%s must fit uint256", field)
	}
	return parsed, nil
}

func decodeSafeExecutionAssuranceCalldata(raw string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if !strings.HasPrefix(value, "0x") && !strings.HasPrefix(value, "0X") {
		return nil, errors.New("data must be 0x-prefixed hex")
	}
	hexData := value[2:]
	if len(hexData)%2 != 0 {
		return nil, errors.New("data must contain an even number of hex characters")
	}
	if len(hexData)/2 > safeExecutionAssuranceMaxDataBytes {
		return nil, fmt.Errorf("data may contain at most %d decoded bytes", safeExecutionAssuranceMaxDataBytes)
	}
	decoded, err := hex.DecodeString(hexData)
	if err != nil {
		return nil, errors.New("data must be valid hex")
	}
	return decoded, nil
}

func validSafeExecutionAssuranceHex32(raw string) bool {
	value := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(raw), "0x"), "0X")
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
