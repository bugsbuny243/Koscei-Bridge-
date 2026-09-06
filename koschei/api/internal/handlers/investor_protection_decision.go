package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"koschei/api/internal/services"
)

const investorProtectionDecisionSchemaV1 = "koschei-investor-protection-decision-v1"

type investorProtectionBasis struct {
	Code           string   `json:"code"`
	Severity       string   `json:"severity"`
	Summary        string   `json:"summary"`
	RuleID         string   `json:"rule_id,omitempty"`
	EvidenceStatus string   `json:"evidence_status,omitempty"`
	EvidenceKeys   []string `json:"evidence_keys,omitempty"`
	Signatures     []string `json:"signatures,omitempty"`
}

type investorProtectionDecision struct {
	SchemaVersion   string                          `json:"schema_version"`
	Decision        string                          `json:"decision"`
	InvestorAction  string                          `json:"investor_action"`
	ExecutionAction string                          `json:"execution_action"`
	Cleared         bool                            `json:"cleared"`
	Grade           string                          `json:"grade"`
	Verdict         string                          `json:"verdict"`
	Summary         string                          `json:"summary"`
	Basis           []investorProtectionBasis       `json:"basis"`
	CriticalGaps    []investigationTransparencyItem `json:"critical_gaps"`
	EvidenceLimits  []investigationTransparencyItem `json:"evidence_limits"`
	Policy          map[string]any                  `json:"policy"`
}

func buildInvestorProtectionDecision(report map[string]any, coverage canonicalIntegrationCoverage, transparency investigationTransparencyReport) investorProtectionDecision {
	verdict := investorProtectionVerdict(report["final_verdict"])
	grade := strings.ToUpper(strings.TrimSpace(verdict.Grade))
	out := investorProtectionDecision{
		SchemaVersion:   investorProtectionDecisionSchemaV1,
		Decision:        "NOT_CLEARED",
		InvestorAction:  "DO_NOT_TREAT_AS_SAFE",
		ExecutionAction: "WITHHOLD",
		Cleared:         false,
		Grade:           grade,
		Verdict:         strings.TrimSpace(verdict.Verdict),
		Basis:           []investorProtectionBasis{},
		CriticalGaps:    append([]investigationTransparencyItem{}, transparency.CollectionGaps...),
		EvidenceLimits:  append([]investigationTransparencyItem{}, transparency.EvidenceLimits...),
		Policy: map[string]any{
			"unknown_is_not_safe":                       true,
			"missing_evidence_cannot_clear_target":      true,
			"verified_hard_risk_precedes_uncertainty":   true,
			"grade_is_not_a_safety_certificate":         true,
			"investor_decision_is_not_financial_advice": true,
		},
	}
	if out.Grade == "" {
		out.Grade = "-"
	}

	verifiedHard := investorVerifiedHardTriggers(verdict.TriggeredRules)
	for _, hit := range verifiedHard {
		out.Basis = append(out.Basis, investorProtectionBasis{
			Code:           "VERIFIED_HARD_TRIGGER",
			Severity:       "critical",
			Summary:        firstInvestorProtectionString(hit.Summary, hit.Title, "Verified hard-risk rule triggered."),
			RuleID:         strings.TrimSpace(hit.RuleID),
			EvidenceStatus: strings.ToLower(strings.TrimSpace(hit.EvidenceStatus)),
			EvidenceKeys:   nonNilInvestorStrings(hit.EvidenceKeys),
			Signatures:     nonNilInvestorStrings(hit.Signatures),
		})
	}

	if len(verifiedHard) > 0 && investorGradeAtLeast(out.Grade, "D") {
		out.Decision = "AVOID"
		out.InvestorAction = "AVOID_TARGET"
		out.ExecutionAction = "BLOCK"
		out.Summary = fmt.Sprintf("Grade %s is backed by %d VERIFIED hard-risk rule(s). Koschei does not clear this target for investment or execution.", out.Grade, len(verifiedHard))
		return out
	}

	if len(verifiedHard) > 0 {
		out.Decision = "REVIEW_FIRST"
		out.InvestorAction = "REQUIRE_EXPERT_REVIEW"
		out.ExecutionAction = "REQUIRE_REVIEW"
		out.Summary = fmt.Sprintf("%d VERIFIED hard-risk rule(s) are present. The target is not cleared for unattended action.", len(verifiedHard))
		return out
	}

	if coverage.OverallStatus == "blocked" || coverage.OverallStatus == "partial" || len(out.CriticalGaps) > 0 || out.Grade == "-" {
		out.Decision = "NOT_CLEARED"
		out.InvestorAction = "DO_NOT_TREAT_AS_SAFE"
		out.ExecutionAction = "WITHHOLD"
		out.Summary = "Critical evidence is incomplete or no safety-clearing grade exists. Missing evidence is not converted into a safe result."
		return out
	}

	switch out.Grade {
	case "D", "E", "F":
		out.Decision = "AVOID"
		out.InvestorAction = "AVOID_TARGET"
		out.ExecutionAction = "BLOCK"
		out.Summary = "The deterministic grade indicates material risk pressure. Koschei does not clear this target for investment or execution."
	case "B", "C":
		out.Decision = "REVIEW_FIRST"
		out.InvestorAction = "REQUIRE_EXPERT_REVIEW"
		out.ExecutionAction = "REQUIRE_REVIEW"
		out.Summary = "Evidence-backed risk pressure is present. Expert review is required before acting."
	case "A":
		out.Decision = "CLEARED_WITH_LIMITS"
		out.InvestorAction = "PROCEED_WITH_LIMITS"
		out.ExecutionAction = "ALLOW_WITH_LIMITS"
		out.Cleared = true
		out.Summary = "No blocking condition is present in the completed evidence set. This is not a guarantee against loss or undiscovered risk."
	default:
		out.Decision = "NOT_CLEARED"
		out.InvestorAction = "DO_NOT_TREAT_AS_SAFE"
		out.ExecutionAction = "WITHHOLD"
		out.Summary = "The investigation does not support a safety clearance."
	}
	return out
}

func investorProtectionVerdict(raw any) services.UnifiedRadarVerdict {
	switch value := raw.(type) {
	case services.UnifiedRadarVerdict:
		return value
	case *services.UnifiedRadarVerdict:
		if value != nil {
			return *value
		}
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return services.UnifiedRadarVerdict{}
	}
	var verdict services.UnifiedRadarVerdict
	if json.Unmarshal(encoded, &verdict) != nil {
		return services.UnifiedRadarVerdict{}
	}
	return verdict
}

func investorVerifiedHardTriggers(hits []services.ActorDefenseRuleHit) []services.ActorDefenseRuleHit {
	out := []services.ActorDefenseRuleHit{}
	for _, hit := range hits {
		if !strings.EqualFold(strings.TrimSpace(hit.EvidenceStatus), "verified") {
			continue
		}
		if !investorHasEvidenceReference(hit) {
			continue
		}
		gradeCap := strings.ToUpper(strings.TrimSpace(hit.GradeCap))
		gradeEffect := strings.ToUpper(strings.TrimSpace(hit.GradeEffect))
		if investorValidGrade(gradeCap) || strings.HasPrefix(gradeEffect, "HARD_CAP_") {
			out = append(out, hit)
		}
	}
	return out
}

func investorHasEvidenceReference(hit services.ActorDefenseRuleHit) bool {
	for _, key := range hit.EvidenceKeys {
		if strings.TrimSpace(key) != "" {
			return true
		}
	}
	for _, signature := range hit.Signatures {
		if strings.TrimSpace(signature) != "" {
			return true
		}
	}
	return false
}

func investorGradeAtLeast(grade, floor string) bool {
	rank := map[string]int{"A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
	return rank[strings.ToUpper(strings.TrimSpace(grade))] >= rank[strings.ToUpper(strings.TrimSpace(floor))]
}

func investorValidGrade(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "A", "B", "C", "D", "E", "F":
		return true
	default:
		return false
	}
}

func firstInvestorProtectionString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func nonNilInvestorStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string{}, values...)
}
