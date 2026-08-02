package services

import (
	"fmt"
	"strings"
	"time"
)

const (
	UnifiedRadarRulesetVersionV110 = "koschei-unified-radar-rules-v1.1.0"
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

// EvaluateUnifiedRadarVerdictV110 preserves all v1.0 decisions and then applies
// the explicit C005 hard ceiling. The existing deterministic signer is reused.
func EvaluateUnifiedRadarVerdictV110(target string, actor ActorDefenseRuleVerdict, behavior UnifiedRadarBehaviorReport) UnifiedRadarVerdict {
	out := EvaluateUnifiedRadarVerdict(target, actor, behavior)
	out.RulesetVersion = UnifiedRadarRulesetVersionV110

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

func worseUnifiedGrade(current, cap string) string {
	rank := map[string]int{"-": 0, "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
	current = strings.ToUpper(strings.TrimSpace(current))
	cap = strings.ToUpper(strings.TrimSpace(cap))
	if rank[current] >= rank[cap] {
		return current
	}
	return cap
}
