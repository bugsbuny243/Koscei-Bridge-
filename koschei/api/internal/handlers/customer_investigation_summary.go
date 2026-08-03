package handlers

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"koschei/api/internal/services"
)

const customerAnalysisSummarySchemaVersion = "koschei-customer-analysis-summary-v2"

func buildCustomerAnalysisSummary(assembly unifiedInvestigationAssembly, hasLiveEvidence bool) map[string]any {
	coverage := customerEvidenceCoverage(assembly.Core.Arms)
	triggered := customerRuleFindings(assembly.UnifiedVerdict.TriggeredRules, false)
	watch := customerRuleFindings(assembly.UnifiedVerdict.WatchFlags, true)
	nonTriggered := customerNonTriggeredObservations(assembly.Behavior)
	unresolved := customerUnresolvedEvidence(assembly.Core.Arms, assembly.Behavior)
	confidence, readiness, confidenceBasis := customerDecisionConfidence(assembly.UnifiedVerdict, hasLiveEvidence, coverage)
	actions := customerRecommendedActions(assembly.UnifiedVerdict, coverage, triggered, watch)

	return map[string]any{
		"schema_version": customerAnalysisSummarySchemaVersion,
		"executive_summary": customerExecutiveSummary(
			assembly.UnifiedVerdict,
			hasLiveEvidence,
			coverage,
			len(triggered),
			len(watch),
		),
		"decision": map[string]any{
			"grade":             assembly.UnifiedVerdict.Grade,
			"verdict":           assembly.UnifiedVerdict.Verdict,
			"signed":            assembly.UnifiedVerdict.Signed,
			"signature":         assembly.UnifiedVerdict.Signature,
			"ruleset_version":   assembly.UnifiedVerdict.RulesetVersion,
			"actor_ruleset":     assembly.UnifiedVerdict.ActorRuleset,
			"confidence":        confidence,
			"readiness":         readiness,
			"confidence_basis":  confidenceBasis,
			"decision_path":     append([]string{}, assembly.UnifiedVerdict.DecisionPath...),
			"narrative_source":  assembly.UnifiedVerdict.NarrativeSource,
			"has_live_evidence": hasLiveEvidence,
		},
		"evidence_coverage":          coverage,
		"grade_changing_findings":    triggered,
		"watch_items":                watch,
		"non_triggered_observations": nonTriggered,
		"unresolved_questions":       unresolved,
		"recommended_actions":        actions,
		"interpretation_policy": map[string]any{
			"missing_evidence_is_not_safe":                   true,
			"verified_or_observed_rules_may_change_grade":    true,
			"inferred_evidence_is_watch_only":                true,
			"unverified_evidence_cannot_change_grade":        true,
			"numeric_final_score_disabled":                   true,
			"numeric_rug_probability_disabled":               true,
			"capability_is_not_proof_of_malicious_intent":    true,
			"bounded_window_absence_is_not_historical_proof": true,
		},
	}
}

func customerEvidenceCoverage(arms []services.SecurityRadarVerdict) map[string]any {
	const architectureArms = 14
	counts := map[string]int{
		"verified":       0,
		"observed":       0,
		"inferred":       0,
		"not_applicable": 0,
		"pending":        0,
	}
	modules := make([]map[string]any, 0, architectureArms)
	for _, arm := range arms {
		state := customerArmEvidenceState(arm)
		counts[state]++
		modules = append(modules, map[string]any{
			"module_id":      arm.ModuleID,
			"module":         arm.Module,
			"state":          state,
			"signed":         arm.Signed,
			"recommendation": arm.Recommendation,
			"evidence_count": len(arm.Evidence),
			"evidence":       append([]string{}, arm.Evidence...),
			"generated_at":   arm.GeneratedAt,
			"rule_version":   arm.RuleVersion,
		})
	}
	if len(arms) < architectureArms {
		counts["pending"] += architectureArms - len(arms)
	}
	sort.Slice(modules, func(i, j int) bool {
		return fmt.Sprint(modules[i]["module_id"]) < fmt.Sprint(modules[j]["module_id"])
	})
	applicable := architectureArms - counts["not_applicable"]
	completed := counts["verified"] + counts["observed"] + counts["inferred"]
	coveragePercent := 0
	if applicable > 0 {
		coveragePercent = int(math.Round(float64(completed) * 100 / float64(applicable)))
	}
	return map[string]any{
		"architecture_arm_count": architectureArms,
		"applicable_arm_count":   applicable,
		"verified":               counts["verified"],
		"observed":               counts["observed"],
		"inferred":               counts["inferred"],
		"not_applicable":         counts["not_applicable"],
		"pending":                counts["pending"],
		"completed":              completed,
		"coverage_percent":       coveragePercent,
		"coverage_is_risk_score": false,
		"modules":                modules,
	}
}

func customerArmEvidenceState(arm services.SecurityRadarVerdict) string {
	execution := strings.ToLower(strings.TrimSpace(customerMapString(arm.Signals, "execution_status")))
	status := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
		customerMapString(arm.Signals, "evidence_status"),
		customerMapString(arm.Signals, "verification_status"),
		customerMapString(arm.Signals, "data_quality"),
	)))
	if customerMapBoolIsFalse(arm.Signals, "applicable") || execution == "not_applicable" || strings.EqualFold(strings.TrimSpace(arm.Recommendation), "not_applicable") {
		return "not_applicable"
	}
	switch status {
	case "verified":
		return "verified"
	case "observed":
		return "observed"
	case "inferred":
		return "inferred"
	}
	switch execution {
	case "verified":
		return "verified"
	case "completed", "observed":
		return "observed"
	case "inferred":
		return "inferred"
	case "evidence_pending", "source_unavailable", "insufficient_evidence", "not_requested":
		return "pending"
	}
	if arm.Signed && (strings.TrimSpace(arm.Signature) != "" || len(arm.Evidence) > 0) {
		return "observed"
	}
	return "pending"
}

func customerRuleFindings(hits []services.ActorDefenseRuleHit, watchOnly bool) []map[string]any {
	out := make([]map[string]any, 0, len(hits))
	for _, hit := range hits {
		severity := "high"
		if watchOnly {
			severity = "watch"
		} else if strings.EqualFold(hit.Tier, "hard_trigger") {
			severity = "critical"
		}
		out = append(out, map[string]any{
			"rule_id":         hit.RuleID,
			"title":           hit.Title,
			"severity":        severity,
			"tier":            hit.Tier,
			"evidence_status": strings.ToLower(strings.TrimSpace(hit.EvidenceStatus)),
			"grade_cap":       hit.GradeCap,
			"grade_effect":    hit.GradeEffect,
			"summary":         hit.Summary,
			"count":           hit.Count,
			"facts":           hit.Facts,
			"evidence_keys":   append([]string{}, hit.EvidenceKeys...),
			"signatures":      append([]string{}, hit.Signatures...),
		})
	}
	return out
}

func customerNonTriggeredObservations(behavior services.UnifiedRadarBehaviorReport) []map[string]any {
	out := []map[string]any{}
	for _, signal := range behavior.Signals {
		status := strings.ToLower(strings.TrimSpace(signal.EvidenceStatus))
		if signal.Triggered || (status != "verified" && status != "observed") {
			continue
		}
		out = append(out, map[string]any{
			"rule_id":         signal.RuleID,
			"title":           signal.Title,
			"evidence_status": status,
			"summary":         signal.Summary,
			"metrics":         signal.Metrics,
			"thresholds":      signal.Thresholds,
			"evidence_keys":   append([]string{}, signal.EvidenceKeys...),
			"signatures":      append([]string{}, signal.Signatures...),
			"observed_at":     signal.ObservedAt,
			"limitations":     append([]string{}, signal.Limitations...),
			"interpretation":  "The explicit threshold was not met in the observed window; this is not a general safety guarantee.",
		})
	}
	return out
}

func customerUnresolvedEvidence(arms []services.SecurityRadarVerdict, behavior services.UnifiedRadarBehaviorReport) []map[string]any {
	out := []map[string]any{}
	seenModules := map[string]bool{}
	for _, arm := range arms {
		if customerArmEvidenceState(arm) != "pending" {
			continue
		}
		moduleID := strings.TrimSpace(arm.ModuleID)
		seenModules[moduleID] = true
		out = append(out, map[string]any{
			"type":         "evidence_arm",
			"module_id":    moduleID,
			"module":       arm.Module,
			"status":       "pending",
			"reason":       firstNonEmptyString(arm.Verdict, arm.Recommendation, "Evidence did not complete in this scan."),
			"grade_effect": "none_until_verified_or_observed",
		})
	}
	for _, signal := range behavior.Signals {
		status := strings.ToLower(strings.TrimSpace(signal.EvidenceStatus))
		if status != "unverified" {
			continue
		}
		out = append(out, map[string]any{
			"type":         "behavior_rule",
			"rule_id":      signal.RuleID,
			"title":        signal.Title,
			"status":       status,
			"reason":       signal.Summary,
			"limitations":  append([]string{}, signal.Limitations...),
			"grade_effect": "none_until_evidence_available",
		})
	}
	if len(arms) < 14 {
		out = append(out, map[string]any{
			"type":                "architecture_coverage",
			"status":              "pending",
			"missing_arm_count":   14 - len(arms),
			"reason":              "The response did not contain all fourteen evidence arms.",
			"grade_effect":        "missing_evidence_is_not_safe",
			"observed_module_ids": customerSortedKeys(seenModules),
		})
	}
	return out
}

func customerDecisionConfidence(final services.UnifiedRadarVerdict, hasLiveEvidence bool, coverage map[string]any) (string, string, []string) {
	pending, _ := coverage["pending"].(int)
	coveragePercent, _ := coverage["coverage_percent"].(int)
	basis := []string{}
	if final.Signed {
		basis = append(basis, "The deterministic final verdict is signed.")
	} else {
		basis = append(basis, "No signed letter-grade verdict was produced.")
	}
	if hasLiveEvidence {
		basis = append(basis, "Live evidence is present in the investigation bundle.")
	} else {
		basis = append(basis, "Live evidence coverage is insufficient.")
	}
	basis = append(basis, fmt.Sprintf("Evidence-arm coverage is %d%% with %d pending arms.", coveragePercent, pending))

	if !final.Signed || !hasLiveEvidence {
		return "low", "evidence_pending", basis
	}
	if pending == 0 && coveragePercent >= 80 {
		return "high", "evidence_complete", basis
	}
	return "medium", "actionable_with_gaps", basis
}

func customerExecutiveSummary(final services.UnifiedRadarVerdict, hasLiveEvidence bool, coverage map[string]any, triggeredCount, watchCount int) string {
	pending, _ := coverage["pending"].(int)
	verified, _ := coverage["verified"].(int)
	observed, _ := coverage["observed"].(int)
	if final.Signed {
		return fmt.Sprintf(
			"A signed deterministic %s verdict was produced from %d grade-changing findings. %d watch items remain non-grade-changing. %d verified and %d observed evidence arms completed; %d arms remain pending.",
			firstNonEmptyString(final.Grade, "letter-grade"), triggeredCount, watchCount, verified, observed, pending,
		)
	}
	liveText := "Live evidence was not sufficient"
	if hasLiveEvidence {
		liveText = "Some live evidence was collected"
	}
	return fmt.Sprintf(
		"No signed letter grade was issued. %s, but the explicit grade rules were not satisfied. %d watch items and %d pending evidence arms remain; missing evidence is not a positive safety signal.",
		liveText, watchCount, pending,
	)
}

func customerRecommendedActions(final services.UnifiedRadarVerdict, coverage map[string]any, triggered, watch []map[string]any) []map[string]any {
	actions := []map[string]any{}
	if len(triggered) > 0 {
		actions = append(actions, map[string]any{
			"priority":         1,
			"action":           "Review every grade-changing rule against its evidence keys and transaction signatures before interacting with the target.",
			"reason":           "The final grade is driven by explicit deterministic rule hits, not a weighted score.",
			"related_rule_ids": customerFindingIDs(triggered),
		})
	}
	pending, _ := coverage["pending"].(int)
	if pending > 0 {
		actions = append(actions, map[string]any{
			"priority": 2,
			"action":   "Complete the pending evidence arms, especially creator, liquidity-control, launch-distribution and transaction-history coverage when applicable.",
			"reason":   fmt.Sprintf("%d evidence arms remain pending; their absence cannot be interpreted as safety.", pending),
		})
	}
	if len(watch) > 0 {
		actions = append(actions, map[string]any{
			"priority":         3,
			"action":           "Monitor watch-only signals and gather verification before treating them as confirmed behavior.",
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

func customerFindingIDs(findings []map[string]any) []string {
	ids := []string{}
	for _, finding := range findings {
		if id := strings.TrimSpace(fmt.Sprint(finding["rule_id"])); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func customerMapString(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func customerMapBoolIsFalse(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	value, exists := values[key]
	if !exists {
		return false
	}
	boolean, ok := value.(bool)
	return ok && !boolean
}

func customerSortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}
