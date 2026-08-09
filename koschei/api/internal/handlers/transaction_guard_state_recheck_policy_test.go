package handlers

import (
	"testing"
)

func intPtr(value int) *int { return &value }

func validPolicyV3Claims() transactionGuardEnforcementPermitClaims {
	return transactionGuardEnforcementPermitClaims{
		Version:                            transactionGuardPolicyBoundPermitVersion,
		StateRecheckPolicyVersion:          transactionGuardStateRecheckPolicyVersion,
		GuardRiskLevel:                     "low",
		GuardRiskIndex:                     intPtr(18),
		StateRecheckCourtRiskThreshold:     intPtr(15),
		StateRecheckCourtRequired:          true,
		StateRecheckCourtRequiredWitnesses: 2,
	}
}

func TestStateRecheckPolicyAcceptsLegacyV2WithoutPolicyClaims(t *testing.T) {
	policy, err := transactionGuardStateRecheckPermitPolicyFromClaims(transactionGuardEnforcementPermitClaims{Version: transactionGuardStateBoundPermitVersion})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.LegacyV2 || policy.PermitVersion != transactionGuardStateBoundPermitVersion || policy.CourtRequired {
		t.Fatalf("policy=%#v", policy)
	}
}

func TestStateRecheckPolicyRejectsLegacyV2WithV3Claims(t *testing.T) {
	claims := transactionGuardEnforcementPermitClaims{
		Version:                   transactionGuardStateBoundPermitVersion,
		StateRecheckPolicyVersion: transactionGuardStateRecheckPolicyVersion,
	}
	if _, err := transactionGuardStateRecheckPermitPolicyFromClaims(claims); err == nil {
		t.Fatal("legacy v2 accepted v3 policy claims")
	}
}

func TestStateRecheckPolicyRequiresCompleteRiskSnapshot(t *testing.T) {
	claims := validPolicyV3Claims()
	claims.GuardRiskIndex = nil
	if _, err := transactionGuardStateRecheckPermitPolicyFromClaims(claims); err == nil {
		t.Fatal("v3 accepted missing guard risk index")
	}
}

func TestStateRecheckPolicyRejectsCourtDecisionThatContradictsSignedThreshold(t *testing.T) {
	claims := validPolicyV3Claims()
	claims.StateRecheckCourtRequired = false
	claims.StateRecheckCourtRequiredWitnesses = 0
	if _, err := transactionGuardStateRecheckPermitPolicyFromClaims(claims); err == nil {
		t.Fatal("v3 accepted Court decision inconsistent with signed risk threshold")
	}
}

func TestStateRecheckCourtRequirementSignedPolicyForcesCourtWhenGlobalOff(t *testing.T) {
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "false")
	claims := validPolicyV3Claims()
	requirement, err := transactionGuardStateRecheckCourtRequirementFromClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	if !requirement.Required || !requirement.SignedPolicy || requirement.GlobalPolicy || requirement.RequiredWitnesses != 2 {
		t.Fatalf("requirement=%#v", requirement)
	}
}

func TestStateRecheckCourtRequirementOptionalPolicyStaysOffWhenGlobalOff(t *testing.T) {
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "false")
	claims := validPolicyV3Claims()
	claims.GuardRiskIndex = intPtr(10)
	claims.StateRecheckCourtRequired = false
	claims.StateRecheckCourtRequiredWitnesses = 0
	requirement, err := transactionGuardStateRecheckCourtRequirementFromClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	if requirement.Required || requirement.SignedPolicy || requirement.GlobalPolicy || requirement.RequiredWitnesses != 0 {
		t.Fatalf("requirement=%#v", requirement)
	}
}

func TestStateRecheckCourtRequirementUsesStricterGlobalWitnessFloor(t *testing.T) {
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "true")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_REQUIRED_WITNESSES", "3")
	claims := validPolicyV3Claims()
	requirement, err := transactionGuardStateRecheckCourtRequirementFromClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	if !requirement.Required || !requirement.SignedPolicy || !requirement.GlobalPolicy || requirement.RequiredWitnesses != 3 {
		t.Fatalf("requirement=%#v", requirement)
	}
}

func TestStateRecheckCourtRequirementLegacyV2UsesCurrentGlobalPolicy(t *testing.T) {
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "true")
	t.Setenv("KOSCHEI_EVIDENCE_COURT_REQUIRED_WITNESSES", "3")
	requirement, err := transactionGuardStateRecheckCourtRequirementFromClaims(transactionGuardEnforcementPermitClaims{Version: transactionGuardStateBoundPermitVersion})
	if err != nil {
		t.Fatal(err)
	}
	if !requirement.Required || requirement.SignedPolicy || !requirement.GlobalPolicy || requirement.RequiredWitnesses != 3 {
		t.Fatalf("requirement=%#v", requirement)
	}
}
