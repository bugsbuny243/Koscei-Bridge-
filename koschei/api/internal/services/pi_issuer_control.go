package services

import (
	"fmt"
	"strings"
)

type PiIssuerControlObservation struct {
	Status                         string `json:"status"`
	EvidenceStatus                 string `json:"evidence_status"`
	ActiveSignerCount              int    `json:"active_signer_count"`
	ActiveSignerWeightSum          int    `json:"active_signer_weight_sum"`
	MediumThreshold                int    `json:"medium_threshold"`
	HighThreshold                  int    `json:"high_threshold"`
	PaymentAuthorizationPossible   bool   `json:"payment_authorization_possible"`
	SetOptionsAuthorizationPossible bool  `json:"set_options_authorization_possible"`
	FutureClassicIssuanceLocked    bool   `json:"future_classic_issuance_locked"`
	MaximumSupplyClaim             bool   `json:"maximum_supply_claim"`
	IdentityClaim                  bool   `json:"identity_claim"`
	Reason                         string `json:"reason"`
}

// enrichPiIssuerControlEvidence interprets only the current signer/threshold
// evidence already collected from the issuer account. Payment authorization is
// medium-threshold; Set Options authorization is high-threshold. A maximum
// supply number is deliberately never inferred from this capability check.
func enrichPiIssuerControlEvidence(analysis ArvisAnalysis, target PiRadarTarget) ArvisAnalysis {
	if target.Kind != piRadarTargetKindAsset {
		return analysis
	}
	for index := range analysis.Arms {
		if analysis.Arms[index].ModuleID != ModuleTokenAuthorityScanner {
			continue
		}
		observation, ok := piIssuerControlFromAuthorityArm(analysis.Arms[index])
		if !ok {
			return analysis
		}
		analysis.Arms[index] = applyPiIssuerControlToAuthorityArm(analysis.Arms[index], observation)
		if analysis.Bundle.Metadata == nil {
			analysis.Bundle.Metadata = map[string]any{}
		}
		analysis.Bundle.Metadata["pi_issuer_control"] = observation
		analysis.Bundle.Metadata["arvis_arms"] = analysis.Arms
		return analysis
	}
	return analysis
}

func piIssuerControlFromAuthorityArm(arm SecurityRadarVerdict) (PiIssuerControlObservation, bool) {
	out := PiIssuerControlObservation{
		Status:             "insufficient_evidence",
		EvidenceStatus:     "insufficient_evidence",
		MaximumSupplyClaim: false,
		IdentityClaim:      false,
		Reason:             "Current issuer signer and threshold evidence is incomplete.",
	}
	if arm.Signals == nil || strings.TrimSpace(fmt.Sprint(arm.Signals["evidence_status"])) != "observed" {
		return out, false
	}
	activeCount, okCount := piSignalInt(arm.Signals["active_signer_count"])
	activeWeight, okWeight := piSignalInt(arm.Signals["active_signer_weight_sum"])
	medium, okMedium := piSignalInt(arm.Signals["medium_threshold"])
	high, okHigh := piSignalInt(arm.Signals["high_threshold"])
	if !okCount || !okWeight || !okMedium || !okHigh || activeCount < 0 || activeWeight < 0 || medium < 0 || high < 0 {
		return out, false
	}

	paymentPossible := piThresholdAuthorizationPossible(activeCount, activeWeight, medium)
	setOptionsPossible := piThresholdAuthorizationPossible(activeCount, activeWeight, high)
	locked := !paymentPossible && !setOptionsPossible
	out = PiIssuerControlObservation{
		Status:                          "observed_current_control",
		EvidenceStatus:                  "observed",
		ActiveSignerCount:               activeCount,
		ActiveSignerWeightSum:           activeWeight,
		MediumThreshold:                 medium,
		HighThreshold:                   high,
		PaymentAuthorizationPossible:    paymentPossible,
		SetOptionsAuthorizationPossible: setOptionsPossible,
		FutureClassicIssuanceLocked:     locked,
		MaximumSupplyClaim:              false,
		IdentityClaim:                   false,
	}
	switch {
	case locked:
		out.Reason = "Observed active signer weights cannot currently authorize either a medium-threshold payment or a high-threshold Set Options operation; future classic issuer payments appear locked by current account authorization state."
	case paymentPossible:
		out.Reason = "Observed active signer weights can currently authorize a medium-threshold payment operation, so ARVIS cannot claim that future classic asset issuance is locked."
	default:
		out.Reason = "Observed active signer weights cannot currently authorize a medium-threshold payment but can authorize high-threshold Set Options, so account controls could be changed and an irreversible issuance lock is not proven."
	}
	return out, true
}

func piThresholdAuthorizationPossible(activeSignerCount, activeWeightSum, threshold int) bool {
	if activeSignerCount <= 0 || activeWeightSum <= 0 {
		return false
	}
	if threshold <= 0 {
		return true
	}
	return activeWeightSum >= threshold
}

func applyPiIssuerControlToAuthorityArm(arm SecurityRadarVerdict, observation PiIssuerControlObservation) SecurityRadarVerdict {
	if arm.Signals == nil {
		arm.Signals = map[string]any{}
	}
	arm.Signals["pi_issuer_control"] = observation
	arm.Signals["future_classic_issuance_locked"] = observation.FutureClassicIssuanceLocked
	arm.Signals["maximum_supply_claim"] = false
	arm.Signals["identity_claim"] = false
	arm.Evidence = append(arm.Evidence, observation.Reason)
	arm.Evidence = append(arm.Evidence, "Issuer authorization state alone does not prove the exact historical maximum supply; ARVIS does not emit a maximum-supply number from this check.")
	return arm
}

func piSignalInt(raw any) (int, bool) {
	switch value := raw.(type) {
	case int:
		return value, true
	case int8:
		return int(value), true
	case int16:
		return int(value), true
	case int32:
		return int(value), true
	case int64:
		return int(value), true
	case uint:
		return int(value), true
	case uint8:
		return int(value), true
	case uint16:
		return int(value), true
	case uint32:
		return int(value), true
	case uint64:
		if uint64(int(value)) != value {
			return 0, false
		}
		return int(value), true
	case float64:
		integer := int(value)
		if float64(integer) != value {
			return 0, false
		}
		return integer, true
	default:
		return 0, false
	}
}
