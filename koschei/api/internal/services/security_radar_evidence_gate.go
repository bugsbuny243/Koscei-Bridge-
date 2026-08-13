package services

const SecurityRadarInsufficientEvidenceMessage = "Real data unavailable. Analysis could not be completed."

func SecurityRadarHasLiveEvidence(bundle SecurityRadarBundle) bool {
	if arms := ArvisArmsFromBundle(bundle); len(arms) > 0 {
		for _, verdict := range arms {
			if verdict.ModuleID == ModuleFinalVerdictEngine {
				continue
			}
			if SecurityRadarVerdictHasVerifiedEvidence(verdict) {
				return true
			}
		}
	}
	for _, verdict := range []SecurityRadarVerdict{bundle.PumpSybilRadar, bundle.RaydiumPoolGuardian, bundle.WalletlessClaimShield} {
		if SecurityRadarVerdictHasVerifiedEvidence(verdict) {
			return true
		}
	}
	return false
}

func EvidenceBackedSecurityRadarBundle(bundle SecurityRadarBundle) SecurityRadarBundle {
	bundle = EnrichArvisBundleWithTransactions(bundle)
	bundle = EnrichArvisBundleWithClaimSurface(bundle)
	bundle = applyResolvedArvisProvider(bundle)
	if SecurityRadarHasLiveEvidence(bundle) {
		return bundle
	}
	bundle.PumpSybilRadar = insufficientEvidenceVerdict(bundle.PumpSybilRadar)
	bundle.RaydiumPoolGuardian = insufficientEvidenceVerdict(bundle.RaydiumPoolGuardian)
	bundle.WalletlessClaimShield = insufficientEvidenceVerdict(bundle.WalletlessClaimShield)
	bundle.CustomerSummary = SecurityRadarInsufficientEvidenceMessage
	bundle.CustomerRecommendation = "insufficient_evidence"
	if bundle.Metadata == nil {
		bundle.Metadata = map[string]any{}
	}
	if arms := ArvisArmsFromBundle(bundle); len(arms) > 0 {
		gated := make([]SecurityRadarVerdict, 0, len(arms))
		for _, arm := range arms {
			gated = append(gated, insufficientEvidenceVerdict(arm))
		}
		bundle.Metadata["arvis_arms"] = gated
		bundle.Metadata["verified_arm_count"] = 0
		bundle.Metadata["runtime_arm_count"] = 0
	}
	bundle.Metadata["final_grade"] = "-"
	bundle.Metadata["final_risk_index"] = 0
	bundle.Metadata["final_risk_level"] = "unknown"
	bundle.Metadata["final_recommendation"] = "insufficient_evidence"
	bundle.Metadata["score_source"] = "none"
	bundle.Metadata["data_quality"] = "no_verified_evidence"
	bundle.Metadata["evidence_status"] = "insufficient_evidence"
	return applyResolvedArvisProvider(bundle)
}

// EvidenceBackedFinalSecurityRadarVerdict is a compatibility projection only.
// Evidence arms may prove facts, but they are never allowed to mint, sign or
// promote a final verdict. EvaluateUnifiedRadarVerdict is the sole grade-bearing
// decision authority for Radar.
func EvidenceBackedFinalSecurityRadarVerdict(bundle SecurityRadarBundle) SecurityRadarFinalVerdict {
	bundle = EvidenceBackedSecurityRadarBundle(bundle)
	if !SecurityRadarHasLiveEvidence(bundle) {
		return SecurityRadarFinalVerdict{Grade: "-", RiskIndex: 0, RiskLevel: "unknown", Verdict: SecurityRadarInsufficientEvidenceMessage, Recommendation: "insufficient_evidence", RuleVersion: SecurityRadarRuleVersion, Signed: false, Signature: ""}
	}
	return arvisCompatibilityFinal()
}

func insufficientEvidenceVerdict(verdict SecurityRadarVerdict) SecurityRadarVerdict {
	if verdict.Signals == nil {
		verdict.Signals = map[string]any{}
	}
	verdict.Grade = "-"
	verdict.RiskIndex = 0
	verdict.RiskLevel = "unknown"
	verdict.Verdict = SecurityRadarInsufficientEvidenceMessage
	verdict.Recommendation = "insufficient_evidence"
	verdict.Signed = false
	verdict.Signature = ""
	verdict.Signals["score_source"] = "none"
	verdict.Signals["verified_evidence"] = false
	verdict.Signals["real_onchain_evidence"] = false
	verdict.Signals["real_offchain_evidence"] = false
	verdict.Signals["data_quality"] = "no_verified_evidence"
	verdict.Signals["evidence_status"] = "insufficient_evidence"
	verdict.Signals["arm_evidence_available"] = false
	verdict.Evidence = []string{SecurityRadarInsufficientEvidenceMessage}
	return verdict
}
