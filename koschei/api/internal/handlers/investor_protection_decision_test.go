package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestInvestorProtectionAvoidsVerifiedFHardTrigger(t *testing.T) {
	report := map[string]any{
		"final_verdict": services.UnifiedRadarVerdict{
			Grade:   "F",
			Verdict: "hard_trigger",
			TriggeredRules: []services.ActorDefenseRuleHit{
				{
					RuleID:         "URD-C005",
					Title:          "Owner-resolved dominant concentration",
					EvidenceStatus: "verified",
					GradeEffect:    "HARD_CAP_F",
					GradeCap:       "F",
					Summary:        "Owner-resolved top ownership concentration exceeded the hard threshold.",
					EvidenceKeys:   []string{"owner:verified-wallet"},
				},
			},
		},
	}
	coverage := canonicalIntegrationCoverage{OverallStatus: "partial"}
	transparency := investigationTransparencyReport{
		CollectionGaps: []investigationTransparencyItem{{Capability: "exit_liquidity", Status: "unavailable", Reason: "provider not configured", Remediable: true}},
		EvidenceLimits: []investigationTransparencyItem{},
	}

	got := buildInvestorProtectionDecision(report, coverage, transparency)
	if got.Decision != "AVOID" || got.ExecutionAction != "BLOCK" || got.Cleared {
		t.Fatalf("verified F hard trigger must block: %#v", got)
	}
	if len(got.Basis) != 1 || got.Basis[0].EvidenceStatus != "verified" {
		t.Fatalf("hard-trigger evidence basis missing: %#v", got.Basis)
	}
	if len(got.CriticalGaps) != 1 {
		t.Fatalf("collection gaps must remain visible even when risk blocks: %#v", got.CriticalGaps)
	}
}

func TestInvestorProtectionMissingEvidenceIsNotCleared(t *testing.T) {
	report := map[string]any{"final_verdict": services.UnifiedRadarVerdict{Grade: "-", Verdict: "no_grade_trigger"}}
	coverage := canonicalIntegrationCoverage{OverallStatus: "blocked"}
	transparency := investigationTransparencyReport{
		CollectionGaps: []investigationTransparencyItem{{Capability: "creator_history", Status: "unavailable", Reason: "provider unavailable", Remediable: true}},
		EvidenceLimits: []investigationTransparencyItem{},
	}

	got := buildInvestorProtectionDecision(report, coverage, transparency)
	if got.Decision != "NOT_CLEARED" || got.ExecutionAction != "WITHHOLD" || got.Cleared {
		t.Fatalf("missing evidence must not become safe/allow: %#v", got)
	}
}

func TestInvestorProtectionCanClearCompletedAGradeOnlyWithLimits(t *testing.T) {
	report := map[string]any{"final_verdict": services.UnifiedRadarVerdict{Grade: "A", Verdict: "completed"}}
	coverage := canonicalIntegrationCoverage{OverallStatus: "complete"}
	transparency := investigationTransparencyReport{EvidenceLimits: []investigationTransparencyItem{}, CollectionGaps: []investigationTransparencyItem{}}

	got := buildInvestorProtectionDecision(report, coverage, transparency)
	if got.Decision != "CLEARED_WITH_LIMITS" || got.ExecutionAction != "ALLOW_WITH_LIMITS" || !got.Cleared {
		t.Fatalf("completed A-grade contract unexpected: %#v", got)
	}
}

func TestInvestorProtectionObservedHardLikeRuleDoesNotBecomeVerifiedBlock(t *testing.T) {
	report := map[string]any{
		"final_verdict": services.UnifiedRadarVerdict{
			Grade:   "F",
			Verdict: "hard_trigger",
			TriggeredRules: []services.ActorDefenseRuleHit{{
				RuleID: "TEST", EvidenceStatus: "observed", GradeEffect: "HARD_CAP_F", GradeCap: "F", EvidenceKeys: []string{"observed:key"},
			}},
		},
	}
	coverage := canonicalIntegrationCoverage{OverallStatus: "complete"}
	got := buildInvestorProtectionDecision(report, coverage, investigationTransparencyReport{})
	if len(got.Basis) != 0 {
		t.Fatalf("OBSERVED rule must not be promoted to VERIFIED hard-trigger basis: %#v", got.Basis)
	}
}

func TestInvestorProtectionVerifiedHardRuleWithoutReferenceIsNotVerifiedBasis(t *testing.T) {
	report := map[string]any{
		"final_verdict": services.UnifiedRadarVerdict{
			Grade:   "F",
			Verdict: "hard_trigger",
			TriggeredRules: []services.ActorDefenseRuleHit{{
				RuleID: "TEST-NO-REF", EvidenceStatus: "verified", GradeEffect: "HARD_CAP_F", GradeCap: "F",
			}},
		},
	}
	coverage := canonicalIntegrationCoverage{OverallStatus: "complete"}
	got := buildInvestorProtectionDecision(report, coverage, investigationTransparencyReport{})
	if len(got.Basis) != 0 {
		t.Fatalf("a VERIFIED label without an evidence key/signature must not become verified investor basis: %#v", got.Basis)
	}
	if got.Cleared {
		t.Fatalf("an evidence-binding gap must never clear a severe target: %#v", got)
	}
}
