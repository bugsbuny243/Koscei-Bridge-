package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"koschei/api/internal/services"
	"koschei/api/internal/web3"
)

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
