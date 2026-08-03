package services

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	UnifiedRadarRulesetVersionV110 = "koschei-unified-radar-rules-v1.1.1"
	UnifiedRuleOwnerConcentration  = "URD-C005"
	UnifiedOwnerConcentrationDCap  = 50.0
	UnifiedOwnerConcentrationFCap  = 70.0
)

// ApplyOwnerConcentrationRuleV110 appends C005 only from owner-resolved,
// risk-bearing holder evidence after infrastructure roles have been excluded.
// Raw token-account concentration is intentionally insufficient.
func ApplyOwnerConcentrationRuleV110(report UnifiedRadarBehaviorReport, holder HolderIntelligence, now time.Time) UnifiedRadarBehaviorReport {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	topOwner := ""
	for _, row := range holder.Rows {
		if row.OwnerResolved && row.RiskBearing && !row.ExcludedFromHolderRisk && strings.TrimSpace(row.OwnerWallet) != "" {
			topOwner = strings.TrimSpace(row.OwnerWallet)
			break
		}
	}
	resolvedScope := holder.Available && holder.OwnerAggregationApplied && holder.CirculatingSupply > 0 && topOwner != ""

	signal := UnifiedRadarSignal{
		RuleID:         UnifiedRuleOwnerConcentration,
		Title:          "Owner-resolved dominant concentration",
		EvidenceStatus: "unverified",
		Triggered:      false,
		GradeEffect:    "none",
		Scope:          "owner_resolved_infrastructure_excluded_circulating_supply",
		Metrics: map[string]any{
			"owner_resolved_top_share_pct": holder.TopOwnerPercentage,
			"owner_aggregation_applied":    holder.OwnerAggregationApplied,
			"risk_bearing_owner_resolved":  topOwner != "",
			"top_owner_wallet":             topOwner,
		},
		Thresholds: map[string]any{
			"d_cap_pct": UnifiedOwnerConcentrationDCap,
			"f_cap_pct": UnifiedOwnerConcentrationFCap,
		},
		EvidenceKeys: []string{},
		Signatures:   []string{},
		Limitations:  []string{},
		ObservedAt:   now.UTC(),
	}

	if !resolvedScope {
		signal.Summary = "Owner-resolved, infrastructure-excluded concentration was unavailable; raw account concentration cannot trigger URD-C005."
		signal.Limitations = append(signal.Limitations, "C005 requires an owner-resolved risk-bearing row, circulating supply and owner aggregation.")
	} else {
		signal.EvidenceStatus = "verified"
		signal.EvidenceKeys = []string{"owner:" + topOwner}
		share := holder.TopOwnerPercentage
		switch {
		case share >= UnifiedOwnerConcentrationFCap:
			signal.Triggered = true
			signal.GradeEffect = "hard_cap_F"
			signal.Summary = fmt.Sprintf("Owner-resolved, infrastructure-excluded top ownership is %.4f%%, meeting the %.0f%% F-cap threshold.", share, UnifiedOwnerConcentrationFCap)
		case share >= UnifiedOwnerConcentrationDCap:
			signal.Triggered = true
			signal.GradeEffect = "hard_cap_D"
			signal.Summary = fmt.Sprintf("Owner-resolved, infrastructure-excluded top ownership is %.4f%%, meeting the %.0f%% D-cap threshold.", share, UnifiedOwnerConcentrationDCap)
		default:
			signal.Summary = fmt.Sprintf("Owner-resolved, infrastructure-excluded top ownership is %.4f%% and did not meet the C005 hard-cap thresholds.", share)
		}
	}

	report.RulesetVersion = UnifiedRadarRulesetVersionV110
	report.Signals = append(report.Signals, signal)
	if signal.Triggered {
		report.TriggeredRuleCount++
	}
	return report
}

// EvaluateUnifiedRadarVerdictV110 is retained as the public compatibility name,
// but emits ruleset v1.1.1. The v1.1.1 correction counts distinct compounding
// rule IDs rather than treating several evidence groups from one rule as several
// grading rules. Evidence groups remain in TriggeredRules for auditability.
func EvaluateUnifiedRadarVerdictV110(target string, actor ActorDefenseRuleVerdict, behavior UnifiedRadarBehaviorReport) UnifiedRadarVerdict {
	base := EvaluateUnifiedRadarVerdict(target, actor, behavior)
	out := base
	out.RulesetVersion = UnifiedRadarRulesetVersionV110
	out.DecisionPath = []string{
		"The 14 legacy evidence arms, actor investigation and market/holder behavior rules are joined in one manual Radar dossier.",
		"No weighted score or 0-100 final result is calculated.",
		"INFERRED is watch-only and UNVERIFIED cannot change the grade.",
	}

	for _, hit := range out.TriggeredRules {
		out.DecisionPath = append(out.DecisionPath, fmt.Sprintf("Rule %s [%s/%s]: %s", hit.RuleID, hit.Tier, hit.EvidenceStatus, hit.Summary))
	}

	if actor.Verdict == "hard_trigger" && actor.Grade != "-" {
		out.Grade = actor.Grade
		out.Verdict = "hard_trigger"
		out.DecisionPath = append(out.DecisionPath, "A VERIFIED actor hard trigger fixed the letter-grade ceiling at "+actor.Grade+".")
	} else {
		distinctIDs := unifiedDistinctCompoundingRuleIDs(out.TriggeredRules)
		holderPressure, holderPressureOK := unifiedRadarSignalByRule(behavior, UnifiedRuleHolderLiquidityPressure)
		dominantExit, dominantExitOK := unifiedRadarSignalByRule(behavior, UnifiedRuleDominantHolderFirstExit)
		pressureRatio := unifiedRadarMetricFloat(holderPressure.Metrics["position_liquidity_ratio"])
		severeCompounding := len(distinctIDs) >= 2 && holderPressureOK && dominantExitOK && holderPressure.Triggered && dominantExit.Triggered && pressureRatio >= 10

		switch {
		case severeCompounding:
			out.Grade = "C"
			out.Verdict = "severe_compounding_rule"
			out.DecisionPath = append(out.DecisionPath, fmt.Sprintf("%d distinct VERIFIED/OBSERVED compounding rule IDs were satisfied: %s.", len(distinctIDs), strings.Join(distinctIDs, ", ")))
			out.DecisionPath = append(out.DecisionPath, fmt.Sprintf("Dominant-holder reference position is %.2fx reported liquidity and a transaction-backed dominant-holder exit is present; severity-aware compounding caps the grade at C.", pressureRatio))
		case len(distinctIDs) >= 2:
			out.Grade = "B"
			out.Verdict = "compounding_rule"
			out.DecisionPath = append(out.DecisionPath, fmt.Sprintf("%d distinct VERIFIED/OBSERVED compounding rule IDs lowered the baseline by one grade to B: %s.", len(distinctIDs), strings.Join(distinctIDs, ", ")))
		case len(distinctIDs) == 1:
			out.Grade = "-"
			out.Verdict = "single_observation"
			out.DecisionPath = append(out.DecisionPath, fmt.Sprintf("Multiple evidence groups may exist, but only one distinct compounding rule ID was satisfied (%s); it cannot issue a letter grade alone.", distinctIDs[0]))
		case len(out.WatchFlags) > 0:
			out.Grade = "-"
			out.Verdict = "watch_only"
			out.DecisionPath = append(out.DecisionPath, "Only watch flags are present; no letter grade is issued.")
		default:
			out.Grade = "-"
			out.Verdict = "no_grade_trigger"
			out.DecisionPath = append(out.DecisionPath, "No grade-changing rule was satisfied; absence of evidence is not an A grade.")
		}
	}

	capGrade := ""
	for _, signal := range behavior.Signals {
		if signal.RuleID != UnifiedRuleOwnerConcentration || !signal.Triggered || signal.EvidenceStatus != "verified" {
			continue
		}
		if signal.GradeEffect == "hard_cap_F" {
			capGrade = "F"
		} else if capGrade == "" && signal.GradeEffect == "hard_cap_D" {
			capGrade = "D"
		}
	}
	if capGrade != "" {
		out.Grade = worseUnifiedGrade(out.Grade, capGrade)
		out.Verdict = "hard_trigger"
		out.DecisionPath = append(out.DecisionPath, "URD-C005 fixed the maximum grade at "+capGrade+" from VERIFIED owner-resolved, infrastructure-excluded concentration.")
	}

	out.Signed = out.Grade != "-" && len(out.TriggeredRules) > 0
	out.Signature = ""
	if out.Signed {
		out.Signature = signUnifiedRadarVerdict(strings.TrimSpace(target), out)
	}
	return out
}

func unifiedDistinctCompoundingRuleIDs(hits []ActorDefenseRuleHit) []string {
	seen := map[string]bool{}
	for _, hit := range hits {
		status := strings.ToLower(strings.TrimSpace(hit.EvidenceStatus))
		if !strings.EqualFold(hit.Tier, "compounding") || (status != "verified" && status != "observed") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(hit.GradeEffect)), "hard_cap_") {
			continue
		}
		if id := strings.TrimSpace(hit.RuleID); id != "" {
			seen[id] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func worseUnifiedGrade(current, cap string) string {
	rank := map[string]int{"-": 0, "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
	current = strings.ToUpper(strings.TrimSpace(current))
	cap = strings.ToUpper(strings.TrimSpace(cap))
	if rank[current] >= rank[cap] {
		return current
	}
	return cap
}
