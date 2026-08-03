package handlers

import (
	"fmt"
	"sort"
	"strings"

	"koschei/api/internal/services"
)

const customerAnalysisSummarySchemaVersionV3 = "koschei-customer-analysis-summary-v3"

// buildCustomerAnalysisSummaryV3 keeps every triggered evidence group visible
// while separating the distinct deterministic rules that actually determined
// the letter grade. Several groups emitted by one rule ID are supporting audit
// context, not several independent grading rules.
func buildCustomerAnalysisSummaryV3(assembly unifiedInvestigationAssembly, hasLiveEvidence bool) map[string]any {
	summary := buildCustomerAnalysisSummary(assembly, hasLiveEvidence)
	allGroups := customerRuleFindings(assembly.UnifiedVerdict.TriggeredRules, false)
	gradeDetermining, supporting, distinctCompounding := customerClassifyTriggeredRuleGroups(assembly.UnifiedVerdict, allGroups)
	coverage, _ := summary["evidence_coverage"].(map[string]any)
	watch, _ := summary["watch_items"].([]map[string]any)

	summary["schema_version"] = customerAnalysisSummarySchemaVersionV3
	summary["triggered_evidence_groups"] = allGroups
	summary["grade_changing_findings"] = gradeDetermining
	summary["supporting_findings"] = supporting
	summary["executive_summary"] = customerExecutiveSummaryV3(assembly.UnifiedVerdict, coverage, len(gradeDetermining), len(supporting), len(distinctCompounding), len(watch))

	decision, _ := summary["decision"].(map[string]any)
	if decision == nil {
		decision = map[string]any{}
		summary["decision"] = decision
	}
	decision["grade_determining_rule_count"] = len(gradeDetermining)
	decision["triggered_evidence_group_count"] = len(allGroups)
	decision["supporting_evidence_group_count"] = len(supporting)
	decision["distinct_compounding_rule_count"] = len(distinctCompounding)
	decision["distinct_compounding_rule_ids"] = distinctCompounding
	decision["grading_semantics"] = "distinct_rule_ids_not_evidence_group_count"

	summary["recommended_actions"] = customerRecommendedActionsV3(assembly.UnifiedVerdict, coverage, gradeDetermining, supporting, watch)
	return summary
}

func customerClassifyTriggeredRuleGroups(final services.UnifiedRadarVerdict, groups []map[string]any) ([]map[string]any, []map[string]any, []string) {
	compounding := map[string][]map[string]any{}
	gradeDetermining := []map[string]any{}
	supporting := []map[string]any{}

	for _, group := range groups {
		id := strings.TrimSpace(fmt.Sprint(group["rule_id"]))
		tier := strings.ToLower(strings.TrimSpace(fmt.Sprint(group["tier"])))
		effect := strings.ToLower(strings.TrimSpace(fmt.Sprint(group["grade_effect"])))
		status := strings.ToLower(strings.TrimSpace(fmt.Sprint(group["evidence_status"])))
		eligible := status == "verified" || status == "observed"
		switch {
		case eligible && (tier == "hard_trigger" || strings.HasPrefix(effect, "hard_cap_")):
			gradeDetermining = append(gradeDetermining, group)
		case eligible && tier == "compounding" && id != "":
			compounding[id] = append(compounding[id], group)
		default:
			supporting = append(supporting, group)
		}
	}

	distinctIDs := make([]string, 0, len(compounding))
	for id := range compounding {
		distinctIDs = append(distinctIDs, id)
	}
	sort.Strings(distinctIDs)

	compoundingDeterminedGrade := final.Verdict == "compounding_rule" || final.Verdict == "severe_compounding_rule"
	for _, id := range distinctIDs {
		groupsForID := compounding[id]
		if compoundingDeterminedGrade && len(distinctIDs) >= 2 {
			gradeDetermining = append(gradeDetermining, customerAggregateRuleGroups(id, groupsForID))
		} else {
			supporting = append(supporting, groupsForID...)
		}
	}

	sort.SliceStable(gradeDetermining, func(i, j int) bool {
		return fmt.Sprint(gradeDetermining[i]["rule_id"]) < fmt.Sprint(gradeDetermining[j]["rule_id"])
	})
	return gradeDetermining, supporting, distinctIDs
}

func customerAggregateRuleGroups(ruleID string, groups []map[string]any) map[string]any {
	if len(groups) == 0 {
		return map[string]any{"rule_id": ruleID}
	}
	base := map[string]any{}
	for key, value := range groups[0] {
		base[key] = value
	}
	evidenceKeys := []string{}
	signatures := []string{}
	for _, group := range groups {
		evidenceKeys = append(evidenceKeys, customerStringSlice(group["evidence_keys"])...)
		signatures = append(signatures, customerStringSlice(group["signatures"])...)
	}
	base["evidence_group_count"] = len(groups)
	base["evidence_keys"] = customerUniqueStrings(evidenceKeys)
	base["signatures"] = customerUniqueStrings(signatures)
	base["summary"] = fmt.Sprintf("%d evidence groups satisfied distinct deterministic rule %s.", len(groups), ruleID)
	return base
}

func customerExecutiveSummaryV3(final services.UnifiedRadarVerdict, coverage map[string]any, determiningCount, supportingCount, distinctCompoundingCount, watchCount int) string {
	pending, _ := coverage["pending"].(int)
	verified, _ := coverage["verified"].(int)
	observed, _ := coverage["observed"].(int)
	if final.Signed {
		return fmt.Sprintf(
			"A signed deterministic %s verdict was produced by %d grade-determining rule. %d triggered evidence groups remain supporting context across %d distinct compounding rule ID. %d watch items remain non-grade-changing. %d verified and %d observed evidence arms completed; %d arms remain pending.",
			firstNonEmptyString(final.Grade, "letter-grade"), determiningCount, supportingCount, distinctCompoundingCount, watchCount, verified, observed, pending,
		)
	}
	return fmt.Sprintf("No signed letter grade was issued. %d supporting evidence groups, %d watch items and %d pending evidence arms remain; missing evidence is not a positive safety signal.", supportingCount, watchCount, pending)
}

func customerRecommendedActionsV3(final services.UnifiedRadarVerdict, coverage map[string]any, determining, supporting, watch []map[string]any) []map[string]any {
	actions := []map[string]any{}
	if len(determining) > 0 {
		actions = append(actions, map[string]any{
			"priority":         1,
			"action":           "Review every grade-determining rule against its complete evidence rows before interacting with the target.",
			"reason":           "The final grade is controlled by distinct deterministic rules, not the number of evidence groups.",
			"related_rule_ids": customerFindingIDs(determining),
		})
	}
	if len(supporting) > 0 {
		actions = append(actions, map[string]any{
			"priority":         2,
			"action":           "Review supporting triggered evidence groups as context without counting repeated groups from one rule as separate grading rules.",
			"reason":           "Supporting evidence can strengthen an investigation while remaining non-determinative for the current letter grade.",
			"related_rule_ids": customerFindingIDs(supporting),
		})
	}
	pending, _ := coverage["pending"].(int)
	if pending > 0 {
		actions = append(actions, map[string]any{
			"priority": 3,
			"action":   "Complete pending evidence arms where applicable.",
			"reason":   fmt.Sprintf("%d evidence arms remain pending; their absence cannot be interpreted as safety.", pending),
		})
	}
	if len(watch) > 0 {
		actions = append(actions, map[string]any{
			"priority":         4,
			"action":           "Gather verification before treating watch-only signals as confirmed behavior.",
			"reason":           "Inferred evidence is intentionally excluded from letter-grade decisions.",
			"related_rule_ids": customerFindingIDs(watch),
		})
	}
	if !final.Signed {
		actions = append(actions, map[string]any{
			"priority": 1,
			"action":   "Do not treat the unsigned result as an approval or a clean bill of health.",
			"reason":   "The evidence did not satisfy the signed deterministic verdict contract.",
		})
	}
	sort.SliceStable(actions, func(i, j int) bool {
		left, _ := actions[i]["priority"].(int)
		right, _ := actions[j]["priority"].(int)
		return left < right
	})
	return actions
}

func customerStringSlice(raw any) []string {
	switch typed := raw.(type) {
	case []string:
		return append([]string{}, typed...)
	case []any:
		out := []string{}
		for _, value := range typed {
			if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return []string{}
	}
}

func customerUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
