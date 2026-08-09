package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"koschei/api/internal/services"
	"koschei/api/internal/web3"
)

type transactionGuardStateRecheckCourtWitnessResponse struct {
	Provider    string `json:"provider"`
	Status      string `json:"status"`
	ValueHash   string `json:"value_hash,omitempty"`
	ContextSlot uint64 `json:"context_slot,omitempty"`
	ErrorClass  string `json:"error_class,omitempty"`
}

type transactionGuardStateRecheckCourtResponse struct {
	SchemaVersion string                                             `json:"schema_version"`
	Enabled       bool                                               `json:"enabled"`
	Method        string                                             `json:"method"`
	Status        string                                             `json:"status"`
	Required      int                                                `json:"required_witnesses"`
	Requested     int                                                `json:"requested_witnesses"`
	Available     int                                                `json:"available_witnesses"`
	Matching      int                                                `json:"matching_witnesses"`
	ValueHash     string                                             `json:"agreed_value_hash,omitempty"`
	MinSlot       uint64                                             `json:"min_context_slot,omitempty"`
	MaxSlot       uint64                                             `json:"max_context_slot,omitempty"`
	SlotSpread    uint64                                             `json:"context_slot_spread,omitempty"`
	Witnesses     []transactionGuardStateRecheckCourtWitnessResponse `json:"witnesses"`
	Limitations   []string                                           `json:"limitations"`
}

func transactionGuardStateRecheckCourtPublicResponse(court web3.EvidenceCourtResult) transactionGuardStateRecheckCourtResponse {
	witnesses := make([]transactionGuardStateRecheckCourtWitnessResponse, 0, len(court.Witnesses))
	for _, witness := range court.Witnesses {
		witnesses = append(witnesses, transactionGuardStateRecheckCourtWitnessResponse{
			Provider:    strings.TrimSpace(witness.Provider),
			Status:      strings.TrimSpace(witness.Status),
			ValueHash:   strings.TrimSpace(witness.ValueHash),
			ContextSlot: witness.ContextSlot,
			ErrorClass:  strings.TrimSpace(witness.ErrorClass),
		})
	}
	return transactionGuardStateRecheckCourtResponse{
		SchemaVersion: court.SchemaVersion,
		Enabled:       court.Enabled,
		Method:        court.Method,
		Status:        court.Status,
		Required:      court.Required,
		Requested:     court.Requested,
		Available:     court.Available,
		Matching:      court.Matching,
		ValueHash:     court.ValueHash,
		MinSlot:       court.MinSlot,
		MaxSlot:       court.MaxSlot,
		SlotSpread:    court.SlotSpread,
		Witnesses:     witnesses,
		Limitations:   append([]string(nil), court.Limitations...),
	}
}

func transactionGuardStateRecheckCourtCanonicalizer(addresses []string) web3.EvidenceCourtCanonicalizer {
	ordered := append([]string(nil), addresses...)
	return func(raw json.RawMessage) (string, uint64, bool, error) {
		var current services.SolanaMultipleAccountInfoResult
		if err := json.Unmarshal(raw, &current); err != nil {
			return "", 0, false, err
		}
		if len(current.Value) != len(ordered) {
			return "", 0, false, fmt.Errorf("provider returned %d accounts for %d witnessed addresses", len(current.Value), len(ordered))
		}
		observed := make([]transactionGuardStateWitnessAccount, 0, len(ordered))
		for index, address := range ordered {
			address = strings.TrimSpace(address)
			if address == "" {
				return "", 0, false, fmt.Errorf("witnessed address is empty")
			}
			stateHash, present, err := transactionGuardAccountStateHash(current.Value[index])
			if err != nil {
				return "", 0, false, err
			}
			observed = append(observed, transactionGuardStateWitnessAccount{Address: address, Present: present, StateHash: stateHash})
		}
		root, err := transactionGuardStateRootFromWitnessAccounts(observed)
		if err != nil {
			return "", 0, false, err
		}
		slot := uint64(0)
		if current.Context.Slot > 0 {
			slot = uint64(current.Context.Slot)
		}
		return root, slot, false, nil
	}
}

func collectTransactionGuardStateRecheckEvidenceCourt(ctx context.Context, network string, addresses []string) web3.EvidenceCourtResult {
	client := web3.NewSolanaRPC(nil)
	params := []any{
		append([]string(nil), addresses...),
		map[string]any{"encoding": "base64", "commitment": "processed"},
	}
	return client.EvidenceCourtWithCanonicalizer(
		ctx,
		network,
		"getMultipleAccounts",
		params,
		transactionGuardStateRecheckCourtCanonicalizer(addresses),
	)
}

func applyTransactionGuardStateRecheckEvidenceCourt(decision transactionGuardStateRecheckDecision, court web3.EvidenceCourtResult) transactionGuardStateRecheckDecision {
	if decision.Status != "state_unchanged" || !court.Enabled {
		return decision
	}

	withhold := func(reason string) transactionGuardStateRecheckDecision {
		decision.Status = "withhold"
		decision.Action = "recheck_required"
		decision.StateUnchanged = false
		decision.RequiresResimulation = true
		decision.Reason = reason
		return decision
	}

	if court.Status != "verified" {
		return withhold("Independent State Witness corroboration did not reach a verified provider quorum; run a fresh simulation before signing.")
	}
	if strings.ToLower(strings.TrimSpace(court.ValueHash)) != strings.ToLower(strings.TrimSpace(decision.CurrentStateRoot)) {
		return withhold("Independent providers reached a state root that disagrees with the primary recheck provider; run a fresh simulation before signing.")
	}
	if decision.SimulationSlot <= 0 {
		return withhold("The signed simulation slot is unavailable for quorum freshness validation.")
	}
	freshMatches := 0
	for _, witness := range court.Witnesses {
		if witness.Status != "observed" {
			continue
		}
		if strings.ToLower(strings.TrimSpace(witness.ValueHash)) != strings.ToLower(strings.TrimSpace(court.ValueHash)) {
			continue
		}
		if witness.ContextSlot < uint64(decision.SimulationSlot) {
			continue
		}
		freshMatches++
	}
	if freshMatches < court.Required {
		return withhold("The provider quorum did not contain enough matching state observations at or after the signed simulation slot; run a fresh simulation before signing.")
	}

	decision.Reason = "The bounded State Witness root still matches the signed Guard decision and is corroborated by an independent provider quorum."
	return decision
}
