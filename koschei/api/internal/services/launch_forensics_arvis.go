package services

import (
	"fmt"
	"time"
)

// ApplyLaunchForensicsToAnalysis replaces the launch-related placeholders with
// mint-specific ATA/ledger evidence. It never rebuilds a final score: the
// unified deterministic rules engine remains the only verdict source.
func ApplyLaunchForensicsToAnalysis(analysis ArvisAnalysis, req SecurityRadarRequest, forensics LaunchForensicsAnalysis) ArvisAnalysis {
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	replacements := map[string]SecurityRadarVerdict{
		ModulePumpSybilRadar:       pumpLaunchBehaviorArm(req, forensics, generatedAt),
		ModuleLaunchDistribution:   launchDistributionArm(req, forensics, generatedAt),
		ModuleSniperTimingDetector: launchSniperTimingArm(req, forensics, generatedAt),
	}
	arms := ArvisArmsFromBundle(analysis.Bundle)
	if len(arms) == 0 {
		arms = append([]SecurityRadarVerdict{}, analysis.Arms...)
	}
	updated := make([]SecurityRadarVerdict, 0, len(arms))
	seen := map[string]bool{}
	for _, arm := range arms {
		if replacement, ok := replacements[arm.ModuleID]; ok {
			updated = append(updated, replacement)
			seen[arm.ModuleID] = true
			continue
		}
		updated = append(updated, arm)
	}
	for moduleID, replacement := range replacements {
		if !seen[moduleID] {
			updated = append(updated, replacement)
		}
	}
	analysis.Arms = updated
	analysis.Final = arvisCompatibilityFinal()
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["arvis_arms"] = updated
	analysis.Bundle.Metadata["architecture_arm_count"] = 14
	analysis.Bundle.Metadata["evidence_arm_count"] = 14
	analysis.Bundle.Metadata["verified_arm_count"] = verifiedArvisEvidenceCount(updated)
	analysis.Bundle.Metadata["runtime_arm_count"] = verifiedArvisEvidenceCount(updated)
	analysis.Bundle.Metadata["launch_distribution"] = forensics
	analysis.Bundle.Metadata["launch_behavior_analysis"] = forensics
	analysis.Bundle.Metadata["final_verdict_source"] = "EvaluateUnifiedRadarVerdict"
	analysis.Bundle.CustomerRecommendation = "evaluate_unified_rules"
	return ApplyArvisInvestigationCoverage(analysis)
}

func launchDistributionArm(req SecurityRadarRequest, forensics LaunchForensicsAnalysis, generatedAt string) SecurityRadarVerdict {
	if !forensics.Available {
		v := evidencePendingArm("Launch Distribution", ModuleLaunchDistribution, req, generatedAt, "Live ledger or mint-specific ATA recipient history is required; missing history is not a safety signal.", "launch_history_incomplete")
		v.Signals["launch_forensics"] = forensics
		for _, limitation := range forensics.Limitations {
			v.Evidence = append(v.Evidence, "Limitation: "+limitation)
		}
		return v
	}
	signals := map[string]any{
		"module_id":                 ModuleLaunchDistribution,
		"real_onchain_evidence":     true,
		"verified_evidence":         true,
		"evidence_status":           "verified_launch_distribution",
		"execution_status":          ArvisExecutionCompleted,
		"collector_attempted":       true,
		"applicable":                true,
		"finding_observed":          true,
		"data_source":               forensics.DataSource,
		"owners_requested":          forensics.OwnersRequested,
		"owners_with_trade_history": forensics.OwnersWithTradeHistory,
		"ledger_trade_count":        forensics.LedgerTradeCount,
		"launch_slot":               forensics.LaunchSlot,
		"launch_time":               forensics.LaunchTime,
		"profiles":                  forensics.Profiles,
		"timeline":                  forensics.Timeline,
		"sniper_count":              forensics.SniperCount,
		"rhythm_bot_count":          forensics.RhythmBotCount,
		"creator_linked_count":      forensics.CreatorLinkedCount,
		"rpc_calls_used":            forensics.RPCCallsUsed,
		"funding_rpc_calls_used":    forensics.FundingRPCCallsUsed,
		"ata_only_policy":           true,
		"recipient_wide_wallet_history_forbidden": true,
		"numeric_score_disabled":                  true,
		"grade_effect":                            "none_at_arm_layer",
	}
	evidence := append([]string{}, forensics.Findings...)
	if len(evidence) == 0 && forensics.Summary != "" {
		evidence = append(evidence, forensics.Summary)
	}
	for _, limitation := range forensics.Limitations {
		evidence = append(evidence, "Limitation: "+limitation)
	}
	arm := evidenceArm("Launch Distribution", ModuleLaunchDistribution, req, 0, signals, evidence, generatedAt)
	arm.Verdict = fmt.Sprintf("Launch Distribution observed mint-specific history for %d owner wallets; this arm reports evidence and does not issue a grade.", forensics.OwnersWithTradeHistory)
	arm.Recommendation = "Compare initial recipients with current top holders and persistent repeat-actor evidence."
	return arm
}

func pumpLaunchBehaviorArm(req SecurityRadarRequest, forensics LaunchForensicsAnalysis, generatedAt string) SecurityRadarVerdict {
	if !forensics.Available {
		v := evidencePendingArm("Pump.fun Sybil Radar", ModulePumpSybilRadar, req, generatedAt, "Mint-specific launch wallet history was not captured; Pump launch coordination cannot be evaluated from holder balances alone.", "pump_launch_history_incomplete")
		v.Signals["launch_forensics"] = forensics
		for _, limitation := range forensics.Limitations {
			v.Evidence = append(v.Evidence, "Limitation: "+limitation)
		}
		return v
	}
	findingObserved := forensics.SniperCount > 0 || forensics.RhythmBotCount > 0 || forensics.CreatorLinkedCount > 0
	signals := map[string]any{
		"module_id":                 ModulePumpSybilRadar,
		"real_onchain_evidence":     true,
		"verified_evidence":         true,
		"evidence_status":           "verified_launch_wallet_behavior",
		"execution_status":          ArvisExecutionCompleted,
		"collector_attempted":       true,
		"applicable":                true,
		"finding_observed":          findingObserved,
		"data_source":               forensics.DataSource,
		"owners_requested":          forensics.OwnersRequested,
		"owners_with_trade_history": forensics.OwnersWithTradeHistory,
		"ledger_trade_count":        forensics.LedgerTradeCount,
		"sniper_count":              forensics.SniperCount,
		"rhythm_bot_count":          forensics.RhythmBotCount,
		"flipper_count":             forensics.FlipperCount,
		"accumulator_count":         forensics.AccumulatorCount,
		"creator_linked_count":      forensics.CreatorLinkedCount,
		"profiles":                  forensics.Profiles,
		"timeline":                  forensics.Timeline,
		"common_ownership_claim":    false,
		"identity_or_intent_claim":  false,
		"numeric_score_disabled":    true,
		"grade_effect":              "none_at_arm_layer",
	}
	evidence := []string{
		fmt.Sprintf("Launch-wallet behavior was analyzed for %d of %d requested owner wallets.", forensics.OwnersWithTradeHistory, forensics.OwnersRequested),
		fmt.Sprintf("Observed launch classifications: sniper=%d, rhythm_bot=%d, flipper=%d, accumulator=%d, creator_linked=%d.", forensics.SniperCount, forensics.RhythmBotCount, forensics.FlipperCount, forensics.AccumulatorCount, forensics.CreatorLinkedCount),
		"Wallet labels describe bounded transaction timing and funding observations; they do not prove common ownership, identity or intent.",
	}
	for _, limitation := range forensics.Limitations {
		evidence = append(evidence, "Limitation: "+limitation)
	}
	arm := evidenceArm("Pump.fun Sybil Radar", ModulePumpSybilRadar, req, 0, signals, evidence, generatedAt)
	if findingObserved {
		arm.Verdict = "Launch-wallet timing, funding or creator-linked behavior was observed in the bounded mint-specific evidence window."
	} else {
		arm.Verdict = "Launch-wallet behavior analysis completed; no sniper, rhythm-bot or creator-linked profile was observed in the bounded evidence window."
	}
	arm.Recommendation = "Correlate observed launch wallets with funding, holder and persistent actor evidence; this arm does not claim common ownership."
	return arm
}

func launchSniperTimingArm(req SecurityRadarRequest, forensics LaunchForensicsAnalysis, generatedAt string) SecurityRadarVerdict {
	if !forensics.Available {
		v := evidencePendingArm("Sniper Timing Detector", ModuleSniperTimingDetector, req, generatedAt, "Parsed acquisition slots or mint-specific launch history are required; missing history is not a negative finding.", "sniper_timing_history_incomplete")
		v.Signals["launch_forensics"] = forensics
		return v
	}
	findingObserved := forensics.SniperCount > 0 || forensics.RhythmBotCount > 0
	signals := map[string]any{
		"module_id":                 ModuleSniperTimingDetector,
		"real_onchain_evidence":     true,
		"verified_evidence":         true,
		"evidence_status":           "verified_launch_timing",
		"execution_status":          ArvisExecutionCompleted,
		"collector_attempted":       true,
		"applicable":                true,
		"finding_observed":          findingObserved,
		"data_source":               forensics.DataSource,
		"launch_slot":               forensics.LaunchSlot,
		"launch_time":               forensics.LaunchTime,
		"owners_with_trade_history": forensics.OwnersWithTradeHistory,
		"sniper_count":              forensics.SniperCount,
		"rhythm_bot_count":          forensics.RhythmBotCount,
		"profiles":                  forensics.Profiles,
		"scope_note":                "Timing coordination is not sole proof of common ownership.",
		"numeric_score_disabled":    true,
		"grade_effect":              "none_at_arm_layer",
	}
	evidence := []string{
		fmt.Sprintf("Launch timing was evaluated for %d owner wallets using %s evidence.", forensics.OwnersWithTradeHistory, forensics.DataSource),
		fmt.Sprintf("Timing classifications observed: sniper=%d, rhythm_bot=%d.", forensics.SniperCount, forensics.RhythmBotCount),
		"A zero observed count applies only to the captured evidence window and is not proof that no coordinated acquisition occurred outside that window.",
	}
	arm := evidenceArm("Sniper Timing Detector", ModuleSniperTimingDetector, req, 0, signals, evidence, generatedAt)
	if findingObserved {
		arm.Verdict = "Mint-specific launch timing evidence contains sniper or rhythm-bot classified wallet behavior."
	} else {
		arm.Verdict = "Launch timing analysis completed; no sniper or rhythm-bot classified wallet was observed in the captured evidence window."
	}
	arm.Recommendation = "Review the launch timeline together with funding and creator-linked evidence."
	return arm
}
