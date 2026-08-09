package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func signTestTransactionGuardClaims(t *testing.T, privateKey ed25519.PrivateKey, claims transactionGuardEnforcementPermitClaims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifyTransactionGuardPolicyBoundPermitV3ForRecheck(t *testing.T) {
	input, witness, _, privateKey, issuedAt := transactionGuardStateRecheckFixture(t, 90*time.Second)
	policy := transactionGuardSignedRecheckPolicy{
		Version:           transactionGuardStateRecheckPolicyVersion,
		RiskLevel:         "low",
		RiskIndex:         18,
		RiskThreshold:     15,
		CourtRequired:     true,
		RequiredWitnesses: 2,
	}
	permit, err := signTransactionGuardEnforcementPermitWithWitnessPolicy(
		privateKey,
		"recheck-key",
		90*time.Second,
		input,
		"req-v3",
		transactionFirewallAssessment{Action: "allow", RiskLevel: "low", RiskIndex: 18},
		issuedAt,
		&witness,
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifyTransactionGuardStateBoundPermitForRecheck(permit.Token, input.Transaction, input.Network, witness, issuedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Version != transactionGuardPolicyBoundPermitVersion || claims.GuardRiskIndex == nil || *claims.GuardRiskIndex != 18 {
		t.Fatalf("claims=%#v", claims)
	}
	if claims.StateRecheckCourtRiskThreshold == nil || *claims.StateRecheckCourtRiskThreshold != 15 || !claims.StateRecheckCourtRequired || claims.StateRecheckCourtRequiredWitnesses != 2 {
		t.Fatalf("policy claims=%#v", claims)
	}
}

func TestVerifyTransactionGuardPolicyBoundPermitRejectsSignedIncompletePolicy(t *testing.T) {
	input, witness, legacyPermit, privateKey, issuedAt := transactionGuardStateRecheckFixture(t, 90*time.Second)
	claims := legacyPermit.Claims
	claims.Version = transactionGuardPolicyBoundPermitVersion
	claims.StateRecheckPolicyVersion = transactionGuardStateRecheckPolicyVersion
	claims.GuardRiskLevel = "low"
	claims.GuardRiskIndex = nil
	claims.StateRecheckCourtRiskThreshold = intPtr(15)
	claims.StateRecheckCourtRequired = true
	claims.StateRecheckCourtRequiredWitnesses = 2
	token := signTestTransactionGuardClaims(t, privateKey, claims)
	if _, err := verifyTransactionGuardStateBoundPermitForRecheck(token, input.Transaction, input.Network, witness, issuedAt.Add(time.Second)); !errors.Is(err, errTransactionGuardPermitInvalid) {
		t.Fatalf("err=%v want permit invalid", err)
	}
}

func TestVerifyTransactionGuardPolicyBoundPermitRejectsSignedContradictoryPolicy(t *testing.T) {
	input, witness, legacyPermit, privateKey, issuedAt := transactionGuardStateRecheckFixture(t, 90*time.Second)
	claims := legacyPermit.Claims
	claims.Version = transactionGuardPolicyBoundPermitVersion
	claims.StateRecheckPolicyVersion = transactionGuardStateRecheckPolicyVersion
	claims.GuardRiskLevel = "low"
	claims.GuardRiskIndex = intPtr(18)
	claims.StateRecheckCourtRiskThreshold = intPtr(15)
	claims.StateRecheckCourtRequired = false
	claims.StateRecheckCourtRequiredWitnesses = 0
	token := signTestTransactionGuardClaims(t, privateKey, claims)
	if _, err := verifyTransactionGuardStateBoundPermitForRecheck(token, input.Transaction, input.Network, witness, issuedAt.Add(time.Second)); !errors.Is(err, errTransactionGuardPermitInvalid) {
		t.Fatalf("err=%v want permit invalid", err)
	}
}
