package handlers

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type transactionGuardStateRecheckRequest struct {
	PermitToken  string                       `json:"permit_token"`
	Transaction  string                       `json:"transaction"`
	Network      string                       `json:"network"`
	StateWitness transactionGuardStateWitness `json:"state_witness"`
}

// TransactionGuardStateRecheck verifies a state-bound Guard permit and then
// re-reads only the bounded account set committed by its signed State Witness.
// It never signs or submits the transaction and never returns raw account data.
func (h *Handler) TransactionGuardStateRecheck(w http.ResponseWriter, r *http.Request) {
	var input transactionGuardStateRecheckRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "invalid_request", "message": "Invalid State Witness recheck request.",
		})
		return
	}
	input.PermitToken = strings.TrimSpace(input.PermitToken)
	input.Transaction = strings.TrimSpace(input.Transaction)
	input.Network = strings.TrimSpace(input.Network)
	if input.Network == "" {
		input.Network = "solana-mainnet"
	}
	if input.PermitToken == "" || input.Transaction == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "state_recheck_input_required", "message": "permit_token and transaction are required.",
		})
		return
	}
	if input.Network != "solana-mainnet" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "unsupported_network", "message": "State Witness recheck currently supports solana-mainnet only.",
		})
		return
	}

	claims, err := verifyTransactionGuardStateBoundPermitForRecheck(
		input.PermitToken,
		input.Transaction,
		input.Network,
		input.StateWitness,
		time.Now().UTC(),
	)
	if err != nil {
		status := http.StatusForbidden
		code := "state_bound_permit_invalid"
		message := "The State Witness permit could not be trusted."
		if errors.Is(err, errTransactionGuardPermitExpired) {
			status = http.StatusConflict
			code = "state_bound_permit_expired"
			message = "The State Witness permit expired; run a fresh Transaction Guard simulation."
		}
		writeJSON(w, status, map[string]any{
			"ok": false, "code": code, "message": message, "requires_resimulation": true,
		})
		return
	}
	permitPolicy, err := transactionGuardStateRecheckPermitPolicyFromClaims(claims)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "code": "state_recheck_policy_invalid", "message": "The signed State Recheck policy could not be trusted.", "requires_resimulation": true,
		})
		return
	}
	courtRequirement, err := transactionGuardStateRecheckCourtRequirementFromClaims(claims)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "code": "state_recheck_policy_unavailable", "message": "The required State Recheck corroboration policy is unavailable; run a fresh simulation before signing.", "requires_resimulation": true,
		})
		return
	}

	addresses := make([]string, 0, len(input.StateWitness.Accounts))
	for _, account := range input.StateWitness.Accounts {
		addresses = append(addresses, account.Address)
	}
	current, ordered, err := services.SolanaGetMultipleAccountsBase64(r.Context(), os.Getenv("SOLANA_RPC_URL"), addresses)
	if err != nil {
		decision := evaluateTransactionGuardStateRecheck(claims, "", 0)
		decision.Reason = "Current account-state evidence could not be collected; run a fresh simulation before signing."
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "code": "state_recheck_unavailable", "decision": decision,
		})
		return
	}
	if len(ordered) != len(input.StateWitness.Accounts) || len(current.Value) != len(ordered) {
		decision := evaluateTransactionGuardStateRecheck(claims, "", current.Context.Slot)
		decision.Reason = "The recheck provider did not return the complete witnessed account set."
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "code": "state_recheck_incomplete", "decision": decision,
		})
		return
	}

	observed := make([]transactionGuardStateWitnessAccount, 0, len(ordered))
	for index, address := range ordered {
		if strings.TrimSpace(address) != strings.TrimSpace(input.StateWitness.Accounts[index].Address) {
			decision := evaluateTransactionGuardStateRecheck(claims, "", current.Context.Slot)
			decision.Reason = "The recheck provider account order did not match the signed witnessed set."
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok": false, "code": "state_recheck_account_mismatch", "decision": decision,
			})
			return
		}
		stateHash, present, hashErr := transactionGuardAccountStateHash(current.Value[index])
		if hashErr != nil {
			decision := evaluateTransactionGuardStateRecheck(claims, "", current.Context.Slot)
			decision.Reason = "A current witnessed account state could not be canonicalized."
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok": false, "code": "state_recheck_hash_unavailable", "decision": decision,
			})
			return
		}
		observed = append(observed, transactionGuardStateWitnessAccount{
			Address: address, Present: present, StateHash: stateHash,
		})
	}
	currentRoot, err := transactionGuardStateRootFromWitnessAccounts(observed)
	if err != nil {
		decision := evaluateTransactionGuardStateRecheck(claims, "", current.Context.Slot)
		decision.Reason = "The current State Witness root could not be computed."
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "code": "state_recheck_root_unavailable", "decision": decision,
		})
		return
	}

	decision := evaluateTransactionGuardStateRecheck(claims, currentRoot, current.Context.Slot)
	response := map[string]any{
		"ok":                      true,
		"safe_to_proceed":         false,
		"product":                 "Koschei Transaction Guard",
		"recheck_version":         transactionGuardStateRecheckVersion,
		"network":                 input.Network,
		"transaction_fingerprint": claims.TransactionFingerprint,
		"signed_recheck_policy":   permitPolicy,
		"court_requirement": map[string]any{
			"required":           courtRequirement.Required,
			"required_witnesses": courtRequirement.RequiredWitnesses,
			"signed_policy":      courtRequirement.SignedPolicy,
			"global_policy":      courtRequirement.GlobalPolicy,
		},
		"decision": decision,
		"warning":  "State Witness recheck confirms only the bounded signed account-state root and never signs or submits the transaction.",
	}
	if decision.Status == "state_unchanged" {
		court := collectTransactionGuardStateRecheckEvidenceCourtWithRequirement(r.Context(), input.Network, addresses, courtRequirement)
		decision = applyTransactionGuardStateRecheckEvidenceCourt(decision, court)
		response["decision"] = decision
		response["evidence_court"] = transactionGuardStateRecheckCourtPublicResponse(court)
		if courtRequirement.Required {
			response["warning"] = "This permit's effective State Recheck policy requires an independent fresh provider quorum before the prior Guard decision may be relied on. Koschei never signs or submits the transaction."
		} else if court.Enabled {
			response["warning"] = "Evidence Court is enabled for this deployment; an independent fresh provider quorum corroborated the bounded State Witness root. Koschei never signs or submits the transaction."
		}
	}
	response["safe_to_proceed"] = transactionGuardStateRecheckSafeToProceed(decision)
	writeJSON(w, http.StatusOK, response)
}
