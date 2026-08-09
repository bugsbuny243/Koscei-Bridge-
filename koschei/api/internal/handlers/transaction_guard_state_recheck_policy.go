package handlers

import (
	"fmt"
	"strings"

	"koschei/api/internal/web3"
)

type transactionGuardStateRecheckPermitPolicy struct {
	PermitVersion     string `json:"permit_version"`
	PolicyVersion     string `json:"policy_version,omitempty"`
	LegacyV2          bool   `json:"legacy_v2"`
	RiskLevel         string `json:"guard_risk_level,omitempty"`
	RiskIndex         int    `json:"guard_risk_index,omitempty"`
	RiskThreshold     int    `json:"court_risk_threshold,omitempty"`
	CourtRequired     bool   `json:"evidence_court_required"`
	RequiredWitnesses int    `json:"required_witnesses,omitempty"`
}

type transactionGuardStateRecheckCourtRequirement struct {
	Required          bool
	RequiredWitnesses int
	SignedPolicy      bool
	GlobalPolicy      bool
}

func validateTransactionGuardStateRecheckPolicyClaims(claims transactionGuardEnforcementPermitClaims) error {
	_, err := transactionGuardStateRecheckPermitPolicyFromClaims(claims)
	return err
}

func transactionGuardStateRecheckPermitPolicyFromClaims(claims transactionGuardEnforcementPermitClaims) (transactionGuardStateRecheckPermitPolicy, error) {
	switch claims.Version {
	case transactionGuardStateBoundPermitVersion:
		if claims.StateRecheckPolicyVersion != "" || claims.GuardRiskLevel != "" || claims.GuardRiskIndex != nil || claims.StateRecheckCourtRiskThreshold != nil || claims.StateRecheckCourtRequired || claims.StateRecheckCourtRequiredWitnesses != 0 {
			return transactionGuardStateRecheckPermitPolicy{}, fmt.Errorf("legacy state-bound permit contains unsupported recheck policy claims")
		}
		return transactionGuardStateRecheckPermitPolicy{
			PermitVersion: claims.Version,
			LegacyV2:      true,
		}, nil
	case transactionGuardPolicyBoundPermitVersion:
		if claims.StateRecheckPolicyVersion != transactionGuardStateRecheckPolicyVersion {
			return transactionGuardStateRecheckPermitPolicy{}, fmt.Errorf("state recheck policy version is unsupported")
		}
		if claims.GuardRiskIndex == nil || claims.StateRecheckCourtRiskThreshold == nil {
			return transactionGuardStateRecheckPermitPolicy{}, fmt.Errorf("state recheck policy risk snapshot is incomplete")
		}
		riskIndex := *claims.GuardRiskIndex
		riskThreshold := *claims.StateRecheckCourtRiskThreshold
		if riskIndex < 0 || riskIndex > 100 || riskThreshold < 0 || riskThreshold > 100 {
			return transactionGuardStateRecheckPermitPolicy{}, fmt.Errorf("state recheck policy risk snapshot is outside bounds")
		}
		riskLevel := strings.ToLower(strings.TrimSpace(claims.GuardRiskLevel))
		switch riskLevel {
		case "low", "medium", "high", "critical", "unknown":
		default:
			return transactionGuardStateRecheckPermitPolicy{}, fmt.Errorf("state recheck policy risk level is invalid")
		}
		expectedCourtRequired := riskIndex >= riskThreshold
		if claims.StateRecheckCourtRequired != expectedCourtRequired {
			return transactionGuardStateRecheckPermitPolicy{}, fmt.Errorf("state recheck court requirement does not match signed risk threshold")
		}
		if claims.StateRecheckCourtRequired {
			if claims.StateRecheckCourtRequiredWitnesses < 2 || claims.StateRecheckCourtRequiredWitnesses > 4 {
				return transactionGuardStateRecheckPermitPolicy{}, fmt.Errorf("state recheck court witness requirement is invalid")
			}
		} else if claims.StateRecheckCourtRequiredWitnesses != 0 {
			return transactionGuardStateRecheckPermitPolicy{}, fmt.Errorf("optional state recheck policy unexpectedly requires court witnesses")
		}
		return transactionGuardStateRecheckPermitPolicy{
			PermitVersion:     claims.Version,
			PolicyVersion:     claims.StateRecheckPolicyVersion,
			RiskLevel:         riskLevel,
			RiskIndex:         riskIndex,
			RiskThreshold:     riskThreshold,
			CourtRequired:     claims.StateRecheckCourtRequired,
			RequiredWitnesses: claims.StateRecheckCourtRequiredWitnesses,
		}, nil
	default:
		return transactionGuardStateRecheckPermitPolicy{}, fmt.Errorf("state-bound permit version is unsupported")
	}
}

func transactionGuardStateRecheckCourtRequirementFromClaims(claims transactionGuardEnforcementPermitClaims) (transactionGuardStateRecheckCourtRequirement, error) {
	policy, err := transactionGuardStateRecheckPermitPolicyFromClaims(claims)
	if err != nil {
		return transactionGuardStateRecheckCourtRequirement{}, err
	}
	globalRequired := web3.EvidenceCourtEnabled()
	required := policy.CourtRequired || globalRequired
	witnesses := 0
	if globalRequired {
		witnesses = web3.EvidenceCourtRequiredWitnesses()
	}
	if policy.CourtRequired && policy.RequiredWitnesses > witnesses {
		witnesses = policy.RequiredWitnesses
	}
	if required && witnesses < 2 {
		return transactionGuardStateRecheckCourtRequirement{}, fmt.Errorf("required state recheck court witness policy is unavailable")
	}
	return transactionGuardStateRecheckCourtRequirement{
		Required:          required,
		RequiredWitnesses: witnesses,
		SignedPolicy:      policy.CourtRequired,
		GlobalPolicy:      globalRequired,
	}, nil
}
