package services

import (
	"fmt"
	"strings"
	"time"
)

const (
	UnifiedRadarRulesetVersionV140           = "koschei-unified-radar-rules-v1.4.0"
	UnifiedRuleCrossTokenExitEventRecurrence = "URD-C008"
	UnifiedExitEventRecurrenceMinimumTargets = 2
)

// ApplyCrossTokenExitEventRecurrenceRuleV140 appends an evidence-only rule from
// the persisted transaction-referenced event corpus. The observation cannot
// alter a grade and is withheld when wallet/target/signature refs are incomplete.
func ApplyCrossTokenExitEventRecurrenceRuleV140(report UnifiedRadarBehaviorReport, recurrence ActorExitRecurrence, now time.Time) UnifiedRadarBehaviorReport {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	actor := strings.TrimSpace(recurrence.ActorWallet)
	otherTargets := uniqueFundingStrings(recurrence.OtherTargets)
	signatures := uniqueFundingStrings(recurrence.Signatures)
	eventKinds := uniqueFundingStrings(recurrence.EventKinds)

	signal := UnifiedRadarSignal{
		RuleID:         UnifiedRuleCrossTokenExitEventRecurrence,
		Title:          "Cross-token exit-event recurrence",
		EvidenceStatus: "unverified",
		Triggered:      false,
		GradeEffect:    "evidence_only",
		Scope:          "persisted_transaction_referenced_cross_token_event_memory",
		Metrics: map[string]any{
			"actor_wallet":                 actor,
			"distinct_targets_with_events": recurrence.DistinctTargetsWithEvents,
			"other_target_mints":           otherTargets,
			"event_kinds":                  eventKinds,
			"current_target":               strings.TrimSpace(recurrence.CurrentTarget),
		},
		Thresholds: map[string]any{
			"minimum_distinct_targets":  UnifiedExitEventRecurrenceMinimumTargets,
			"requires_actor_wallet_ref": true,
			"requires_other_target_ref": true,
			"requires_signature_ref":    true,
		},
		EvidenceKeys: []string{},
		Signatures:   append([]string{}, signatures...),
		ObservedAt:   now,
		Limitations:  append([]string{}, recurrence.Limitations...),
	}

	switch {
	case !recurrence.Available:
		signal.Summary = "Cross-token event memory was unavailable; URD-C008 was not evaluated as evidence."
	case recurrence.DistinctTargetsWithEvents < UnifiedExitEventRecurrenceMinimumTargets:
		signal.Summary = "Fewer than two token targets carry transaction-referenced event observations for this wallet; URD-C008 did not fire."
	case !recurrence.ReferencesComplete || actor == "" || len(otherTargets) == 0 || len(signatures) == 0:
		signal.Summary = "Cross-token event counts existed, but wallet, target and transaction-signature references were incomplete; URD-C008 was withheld."
		signal.Limitations = append(signal.Limitations, "URD-C008 requires the wallet, at least one different target mint, and cited transaction signatures before it can fire.")
	default:
		signal.Triggered = true
		if recurrence.EvidenceStatus == "verified" {
			signal.EvidenceStatus = "verified"
		} else {
			signal.EvidenceStatus = "observed"
		}
		signal.EvidenceKeys = append(signal.EvidenceKeys, "event-actor:"+actor)
		for _, target := range otherTargets {
			signal.EvidenceKeys = append(signal.EvidenceKeys, "event-target:"+target)
		}
		for _, signature := range signatures {
			signal.EvidenceKeys = append(signal.EvidenceKeys, "event-signature:"+signature)
		}
		signal.EvidenceKeys = uniqueFundingStrings(signal.EvidenceKeys)
		signal.Summary = fmt.Sprintf("This wallet has transaction-referenced on-chain event observations on %d distinct token targets.", recurrence.DistinctTargetsWithEvents)
	}

	report.RulesetVersion = UnifiedRadarRulesetVersionV140
	report.Signals = append(report.Signals, signal)
	if signal.Triggered {
		report.TriggeredRuleCount++
	}
	return report
}

// EvaluateUnifiedRadarVerdictV140 preserves v1.3 grading exactly and attaches
// URD-C008 only after the grading decision. C008 therefore cannot issue a grade
// or signed verdict by itself.
func EvaluateUnifiedRadarVerdictV140(target string, actor ActorDefenseRuleVerdict, behavior UnifiedRadarBehaviorReport) UnifiedRadarVerdict {
	gradingBehavior := behavior
	gradingBehavior.Signals = make([]UnifiedRadarSignal, 0, len(behavior.Signals))
	for _, signal := range behavior.Signals {
		if signal.RuleID != UnifiedRuleCrossTokenExitEventRecurrence {
			gradingBehavior.Signals = append(gradingBehavior.Signals, signal)
		}
	}
	out := EvaluateUnifiedRadarVerdictV130(target, actor, gradingBehavior)
	out.RulesetVersion = UnifiedRadarRulesetVersionV140
	for _, signal := range behavior.Signals {
		if signal.RuleID != UnifiedRuleCrossTokenExitEventRecurrence || !signal.Triggered {
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
