package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func policyBoundPermitFixture(t *testing.T) (ed25519.PrivateKey, transactionGuardV2Request, transactionGuardStateWitness) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(70 + i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	input := transactionGuardV2Request{Transaction: "policy-bound-transaction", Network: "solana-mainnet", Encoding: "base64"}
	witness := buildTransactionGuardStateWitness(
		transactionFingerprint(input.Transaction),
		500,
		502,
		[]string{"AddrPolicy"},
		[]*services.SolanaAccountInfo{{Lamports: 99, Owner: "OwnerPolicy", Data: []any{"UA==", "base64"}}},
	)
	if !witness.Complete {
		t.Fatalf("witness=%#v", witness)
	}
	return privateKey, input, witness
}

func TestBuildTransactionGuardEnforcementStateIssuesPolicyBoundPermitV3(t *testing.T) {
	privateKey, input, witness := policyBoundPermitFixture(t)
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "true")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "guard-policy-v3")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(privateKey))
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS", "90")
	t.Setenv("TRANSACTION_GUARD_STATE_RECHECK_COURT_RISK_THRESHOLD", "15")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_REQUIRED_WITNESSES", "2")

	assessment := transactionFirewallAssessment{Action: "allow", RiskLevel: "low", RiskIndex: 18}
	state := buildTransactionGuardEnforcementStateWithWitness(input, "req-policy-v3", assessment, true, time.Unix(1_800_000_000, 0).UTC(), &witness)
	if !state.Issued || state.Permit == nil || state.Permit.Version != transactionGuardPolicyBoundPermitVersion {
		t.Fatalf("state=%#v", state)
	}
	claims := state.Permit.Claims
	if claims.GuardRiskIndex == nil || *claims.GuardRiskIndex != 18 || claims.StateRecheckCourtRiskThreshold == nil || *claims.StateRecheckCourtRiskThreshold != 15 {
		t.Fatalf("claims=%#v", claims)
	}
	if !claims.StateRecheckCourtRequired || claims.StateRecheckCourtRequiredWitnesses != 2 {
		t.Fatalf("court policy=%#v", claims)
	}
}

func TestBuildTransactionGuardSignedRecheckPolicyKeepsCourtOptionalBelowThreshold(t *testing.T) {
	policy, err := buildTransactionGuardSignedRecheckPolicy(
		transactionFirewallAssessment{Action: "allow", RiskLevel: "low", RiskIndex: 10},
		15,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if policy.CourtRequired || policy.RequiredWitnesses != 0 || policy.RiskThreshold != 15 || policy.RiskIndex != 10 {
		t.Fatalf("policy=%#v", policy)
	}
}

func TestPolicyBoundPermitSignerRejectsInconsistentCourtDecision(t *testing.T) {
	privateKey, input, witness := policyBoundPermitFixture(t)
	policy := transactionGuardSignedRecheckPolicy{
		Version:       transactionGuardStateRecheckPolicyVersion,
		RiskLevel:     "low",
		RiskIndex:     18,
		RiskThreshold: 15,
		CourtRequired: false,
	}
	if _, err := signTransactionGuardEnforcementPermitWithWitnessPolicy(
		privateKey,
		"guard-policy-v3",
		90*time.Second,
		input,
		"req-inconsistent-policy",
		transactionFirewallAssessment{Action: "allow", RiskLevel: "low", RiskIndex: 18},
		time.Unix(1_800_000_000, 0).UTC(),
		&witness,
		policy,
	); err == nil {
		t.Fatal("inconsistent signed Court policy was accepted")
	}
}
