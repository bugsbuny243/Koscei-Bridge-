package services

import (
	"fmt"
	"testing"
)

func TestHolderClusterTierAssignmentExcludesProtocolInventory(t *testing.T) {
	accounts := []HolderRoleAccount{{Rank: 1, OwnerWallet: "LP", Balance: 1000, Role: "pump_liquidity_vault", ExcludedFromHolderRisk: true}}
	for i := 0; i < 12; i++ {
		accounts = append(accounts, HolderRoleAccount{Rank: i + 2, OwnerWallet: "Wallet" + string(rune('A'+i)), Balance: float64(100 - i), Role: "externally_owned_wallet"})
	}
	candidates := holderClusterRiskOwnerCandidates(accounts, 20)
	if len(candidates) != 12 {
		t.Fatalf("candidate count = %d", len(candidates))
	}
	if candidates[0].OwnerWallet == "LP" {
		t.Fatal("LP/protocol inventory consumed a deep slot")
	}
	cfg := holderScanTierConfig{DeepSignatureLimit: 100, DeepTransactionLimit: 10, ShallowSignatureLimit: 20, ShallowTransactionLimit: 2, DeepOwnerCount: 8, RPCBudget: 600}
	plans := holderClusterAssignScanTiers(candidates, cfg)
	for i, plan := range plans {
		expected := "shallow"
		if i < 8 {
			expected = "deep"
		}
		if plan.Tier != expected {
			t.Fatalf("plan %d tier = %s, want %s", i, plan.Tier, expected)
		}
	}
}

func TestHolderClusterTierAssignmentDegradesWhenBudgetCannotFitDeep(t *testing.T) {
	candidates := []HolderRoleAccount{
		{OwnerWallet: "A", Balance: 3, Role: "externally_owned_wallet"},
		{OwnerWallet: "B", Balance: 2, Role: "externally_owned_wallet"},
	}
	cfg := holderScanTierConfig{DeepSignatureLimit: 100, DeepTransactionLimit: 10, ShallowSignatureLimit: 20, ShallowTransactionLimit: 2, DeepOwnerCount: 2, RPCBudget: 6}
	plans := holderClusterAssignScanTiers(candidates, cfg)
	if plans[0].Tier != "shallow" || !plans[0].BudgetDegraded {
		t.Fatalf("first plan = %#v", plans[0])
	}
	if plans[1].Tier != "shallow" || !plans[1].BudgetDegraded {
		t.Fatalf("second plan = %#v", plans[1])
	}
}

func TestHolderClusterTransactionIndexesRespectTierLimit(t *testing.T) {
	signatures := make([]SolanaSignatureInfo, 12)
	for i := range signatures {
		signatures[i].Signature = "sig"
	}
	if got := len(holderClusterTransactionIndexesForLimit(signatures, 0, 2)); got != 2 {
		t.Fatalf("shallow indexes = %d", got)
	}
	if got := len(holderClusterTransactionIndexesForLimit(signatures, 0, 10)); got != 10 {
		t.Fatalf("deep indexes = %d", got)
	}
}

func TestHolderClusterEnhancedTransactionsRespectTierLimit(t *testing.T) {
	transactions := make([]heliusEnhancedTransaction, 30)
	for index := range transactions {
		transactions[index].Signature = fmt.Sprintf("sig-%d", index)
		transactions[index].Timestamp = int64(1000 - index)
	}
	if got := len(holderClusterEnhancedTransactionsForLimit(transactions, 975, 2)); got != 2 {
		t.Fatalf("standard enhanced parsed transactions = %d, want 2", got)
	}
	if got := len(holderClusterEnhancedTransactionsForLimit(transactions, 975, 20)); got != 20 {
		t.Fatalf("deep enhanced parsed transactions = %d, want 20", got)
	}
}
