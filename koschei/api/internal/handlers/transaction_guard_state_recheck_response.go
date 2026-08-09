package handlers

import "strings"

func transactionGuardStateRecheckSafeToProceed(decision transactionGuardStateRecheckDecision) bool {
	return decision.Version == transactionGuardStateRecheckVersion &&
		decision.Status == "state_unchanged" &&
		decision.Action == "permit_state_consistent" &&
		decision.StateUnchanged &&
		!decision.RequiresResimulation &&
		strings.TrimSpace(decision.IssuedStateRoot) != "" &&
		strings.TrimSpace(decision.CurrentStateRoot) != "" &&
		decision.IssuedStateRoot == decision.CurrentStateRoot &&
		decision.SimulationSlot > 0 &&
		decision.CurrentStateSlot >= decision.SimulationSlot
}
