package executionproof

import (
	"math/big"
	"strings"
)

// SafeOutflowBudgetVerifier enforces transaction-wide cumulative outflow
// budgets. Checking each movement independently is insufficient because several
// individually-valid transfers can exceed one approved maximum in aggregate.
//
// This verifier is deliberately side-effect free and fail-closed.
type SafeOutflowBudgetVerifier struct{}

func (SafeOutflowBudgetVerifier) Verify(policy SafeContainmentPolicy, movements []SafeAssetMovement) bool {
	type budgetKey struct {
		kind  string
		token string
		to    string
		id    string
	}

	limits := make(map[budgetKey]*big.Int, len(policy.AllowedOutflow))
	for _, bound := range policy.AllowedOutflow {
		if !validOutflowBound(bound) {
			return false
		}
		key := budgetKey{
			kind:  strings.ToLower(strings.TrimSpace(bound.Kind)),
			token: normalizeOptionalAddress(bound.Token),
			to:    normalizeAddress(bound.To),
			id:    strings.TrimSpace(bound.ID),
		}
		max, ok := new(big.Int).SetString(strings.TrimSpace(bound.MaxAmount), 10)
		if !ok || max.Sign() < 0 {
			return false
		}
		// Duplicate policy rows are ambiguous authority. Reject them rather than
		// accidentally granting multiple independent budgets for the same route.
		if _, exists := limits[key]; exists {
			return false
		}
		limits[key] = max
	}

	used := make(map[budgetKey]*big.Int, len(limits))
	safe := normalizeAddress(policy.Safe)
	for _, movement := range movements {
		if !validAssetMovement(movement) {
			return false
		}
		if normalizeAddress(movement.From) != safe {
			continue
		}

		key := budgetKey{
			kind:  strings.ToLower(strings.TrimSpace(movement.Kind)),
			token: normalizeOptionalAddress(movement.Token),
			to:    normalizeAddress(movement.To),
			id:    strings.TrimSpace(movement.ID),
		}
		limit, exists := limits[key]
		if !exists {
			return false
		}
		amount, ok := new(big.Int).SetString(strings.TrimSpace(movement.Amount), 10)
		if !ok || amount.Sign() < 0 {
			return false
		}
		if used[key] == nil {
			used[key] = new(big.Int)
		}
		used[key].Add(used[key], amount)
		if used[key].Cmp(limit) > 0 {
			return false
		}
	}
	return true
}
