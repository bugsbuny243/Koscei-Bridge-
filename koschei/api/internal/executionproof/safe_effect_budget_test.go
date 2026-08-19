package executionproof

import (
	"context"
	"testing"

	"koschei/api/internal/matrixcontainment"
)

func TestSafeOutflowBudgetVerifierRejectsAggregateOverflow(t *testing.T) {
	policy := SafeContainmentPolicy{
		Version: SafeContainmentPolicyVersion,
		Safe:    "0x1111111111111111111111111111111111111111",
		AllowedOutflow: []SafeOutflowBound{{
			Kind:      "native",
			To:        "0x2222222222222222222222222222222222222222",
			MaxAmount: "100",
		}},
	}
	movements := []SafeAssetMovement{
		{Kind: "native", From: policy.Safe, To: policy.AllowedOutflow[0].To, Amount: "60"},
		{Kind: "native", From: policy.Safe, To: policy.AllowedOutflow[0].To, Amount: "60"},
	}
	if (SafeOutflowBudgetVerifier{}).Verify(policy, movements) {
		t.Fatal("aggregate outflow 120 escaped max 100")
	}
}

func TestSafeOutflowBudgetVerifierAllowsAggregateAtLimit(t *testing.T) {
	policy := SafeContainmentPolicy{
		Version: SafeContainmentPolicyVersion,
		Safe:    "0x1111111111111111111111111111111111111111",
		AllowedOutflow: []SafeOutflowBound{{
			Kind:      "erc20",
			Token:     "0x3333333333333333333333333333333333333333",
			To:        "0x2222222222222222222222222222222222222222",
			MaxAmount: "100",
		}},
	}
	movements := []SafeAssetMovement{
		{Kind: "erc20", Token: policy.AllowedOutflow[0].Token, From: policy.Safe, To: policy.AllowedOutflow[0].To, Amount: "40"},
		{Kind: "erc20", Token: policy.AllowedOutflow[0].Token, From: policy.Safe, To: policy.AllowedOutflow[0].To, Amount: "60"},
	}
	if !(SafeOutflowBudgetVerifier{}).Verify(policy, movements) {
		t.Fatal("aggregate outflow exactly at approved limit was rejected")
	}
}

func TestSafeOutflowBudgetVerifierRejectsDuplicateAuthorityRows(t *testing.T) {
	bound := SafeOutflowBound{
		Kind:      "native",
		To:        "0x2222222222222222222222222222222222222222",
		MaxAmount: "100",
	}
	policy := SafeContainmentPolicy{
		Version:        SafeContainmentPolicyVersion,
		Safe:           "0x1111111111111111111111111111111111111111",
		AllowedOutflow: []SafeOutflowBound{bound, bound},
	}
	if (SafeOutflowBudgetVerifier{}).Verify(policy, nil) {
		t.Fatal("duplicate outflow authority rows must fail closed")
	}
}

func TestSafeIsolatedRunnerContainsAggregateOutflowOverflow(t *testing.T) {
	input, action, policy, evidence := safeRunnerFixture(t)
	policy.AllowedOutflow[0].MaxAmount = "100"
	policyHash, err := safeContainmentPolicySHA256(policy)
	if err != nil {
		t.Fatal(err)
	}
	input.InvariantSetSHA256 = policyHash
	evidence.AssetMovements = []SafeAssetMovement{
		{Kind: "native", From: policy.Safe, To: policy.AllowedOutflow[0].To, Amount: "60"},
		{Kind: "native", From: policy.Safe, To: policy.AllowedOutflow[0].To, Amount: "60"},
	}
	runner := SafeIsolatedRunner{Backend: stubSafeIsolatedBackend{evidence: evidence}, Policy: policy}
	receipt, err := matrixcontainment.EvaluateWithRunner(context.Background(), input, action, runner)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Decision != matrixcontainment.DecisionContain {
		t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons)
	}
}
