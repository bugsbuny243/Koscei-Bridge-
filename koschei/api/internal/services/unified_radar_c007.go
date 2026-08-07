package services

import (
	"fmt"
	"strings"
	"time"
)

const (
	UnifiedRadarRulesetVersionV130             = "koschei-unified-radar-rules-v1.3.0"
	UnifiedRuleCrossTokenFundingRecurrence     = "URD-C007"
	UnifiedFundingRecurrenceMinimumTargetCount = 2
)

// ApplyCrossTokenFundingRecurrenceRuleV130 appends an evidence-only rule from
// the persisted funding corpus. It cannot fire unless a current shared funder
// has another target reference. A rollup count without funder-plus-target refs
// is deliberately withheld rather than promoted to OBSERVED evidence.
func ApplyCrossTokenFundingRecurrenceRuleV130(report UnifiedRadarBehaviorReport, recurrence FundingRecurrenceAnalysis, now time.Time) UnifiedRadarBehaviorReport {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()

	funders := []string{}
	otherTargets := []string{}
	memberWallets := []string{}
	maxDistinctTargets := 0
	storedRowsVerified := true
	referenceGap := false
	qualifying := 0
	for _, source := range recurrence.Sources {
		if source.DistinctTargets < UnifiedFundingRecurrenceMinimumTargetCount {
			continue
		}
		if !source.ReferencesComplete || strings.TrimSpace(source.FundingSource) == "" || len(source.OtherTargets) == 0 {
			referenceGap = true
			continue
		}
		qualifying++
		funders = append(funders, source.FundingSource)
		otherTargets = append(otherTargets, source.OtherTargets...)
		memberWallets = append(memberWallets, source.MemberWallets...)
		if source.DistinctTargets > maxDistinctTargets {
			maxDistinctTargets = source.DistinctTargets
		}
		if !source.StoredRowsVerified {
			storedRowsVerified = false
		}
	}
	funders = uniqueFundingStrings(funders)
	otherTargets = uniqueFundingStrings(otherTargets)
	memberWallets = uniqueFundingStrings(memberWallets)

	signal := UnifiedRadarSignal{
		RuleID:         UnifiedRuleCrossTokenFundingRecurrence,
		Title:          "Cross-token funding source recurrence",
		EvidenceStatus: "unverified",
		Triggered:      false,
		GradeEffect:    "evidence_only",
		Scope:          "persisted_shared_funder_cross_token_memory",
		Metrics: map[string]any{
			"funding_sources":         funders,
			"other_target_mints":      otherTargets,
			"member_wallets":          memberWallets,
			"max_distinct_targets":    maxDistinctTargets,
			"qualifying_source_count": qualifying,
			"current_target":          strings.TrimSpace(recurrence.CurrentTarget),
		},
		Thresholds: map[string]any{
			"minimum_distinct_targets":   UnifiedFundingRecurrenceMinimumTargetCount,
			"requires_other_target_ref":  true,
			"requires_funder_wallet_ref": true,
		},
		EvidenceKeys: []string{},
		Signatures:   []string{},
		ObservedAt:   now,
		Limitations:  append([]string{}, recurrence.Limitations...),
	}

	switch {
	case !recurrence.Available:
		signal.Summary = "Funding recurrence corpus was unavailable; URD-C007 was not evaluated as evidence."
	case referenceGap && qualifying == 0:
		signal.Summary = "Cross-token funding recurrence count existed but funder wallet plus other target-mint references were incomplete; URD-C007 was withheld."
		signal.Limitations = append(signal.Limitations, "URD-C007 requires the funder wallet and at least one different target mint before it can fire.")
	case qualifying == 0:
		signal.Summary = "No current shared funding source was observed on two or more token targets; URD-C007 did not fire."
	default:
		signal.Triggered = true
		if storedRowsVerified {
			signal.EvidenceStatus = "verified"
		} else {
			signal.EvidenceStatus = "observed"
			signal.Limitations = append(signal.Limitations, "At least one recurrence row lacked complete member-wallet or observation-timestamp evidence; VERIFIED was not used.")
		}
		for _, funder := range funders {
			signal.EvidenceKeys = append(signal.EvidenceKeys, "funding-source:"+funder)
		}
		for _, target := range otherTargets {
			signal.EvidenceKeys = append(signal.EvidenceKeys, "funding-target:"+target)
		}
		signal.EvidenceKeys = uniqueFundingStrings(signal.EvidenceKeys)
		signal.Summary = fmt.Sprintf("%d shared funding source(s) recur across token targets; strongest source appears on %d targets.", qualifying, maxDistinctTargets)
	}

	report.RulesetVersion = UnifiedRadarRulesetVersionV130
	report.Signals = append(report.Signals, signal)
	if signal.Triggered {
		report.TriggeredRuleCount++
	}
	return report
}

// EvaluateUnifiedRadarVerdictV130 keeps C007 evidence in the acceptance chain
// without allowing the corpus observation itself to lower a grade. Grading is
// first computed by v1.2.0 with C007 removed, then the evidence-only hit is
// attached and the signed contract is regenerated if another rule graded it.
func EvaluateUnifiedRadarVerdictV130(target string, actor ActorDefenseRuleVerdict, behavior UnifiedRadarBehaviorReport) UnifiedRadarVerdict {
	gradingBehavior := behavior
	gradingBehavior.Signals = make([]UnifiedRadarSignal, 0, len(behavior.Signals))
	for _, signal := range behavior.Signals {
		if signal.RuleID != UnifiedRuleCrossTokenFundingRecurrence {
			gradingBehavior.Signals = append(gradingBehavior.Signals, signal)
		}
	}
	out := EvaluateUnifiedRadarVerdictV120(target, actor, gradingBehavior)
	out.RulesetVersion = UnifiedRadarRulesetVersionV130
	for _, signal := range behavior.Signals {
		if signal.RuleID != UnifiedRuleCrossTokenFundingRecurrence || !signal.Triggered {
			continue
		}
		if signal.EvidenceStatus != "verified" && signal.EvidenceStatus != "observed" {
			continue
		}
		out.TriggeredRules = append(out.TriggeredRules, unifiedSignalRuleHit(signal))
		out.DecisionPath = append(out.DecisionPath, fmt.Sprintf("Rule %s [%s] is evidence-only and cannot alter the letter grade: %s", signal.RuleID, signal.EvidenceStatus, signal.Summary))
	}
	actorRuleSortHits(out.TriggeredRules)
	out.Signed = out.Grade != "-" && len(out.TriggeredRules) > 0
	if out.Signed {
		out.Signature = signUnifiedRadarVerdict(strings.TrimSpace(target), out)
	} else {
		out.Signature = ""
	}
	return out
}
