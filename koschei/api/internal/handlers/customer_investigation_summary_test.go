package handlers

import (
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestCustomerAnalysisSummaryExposesEvidenceDecisionAndActions(t *testing.T) {
	assembly := unifiedInvestigationAssembly{
		Core: holderIntelligenceCoreResult{
			Request: services.SecurityRadarRequest{Target: "Mint111", Network: "solana-mainnet"},
			Arms: []services.SecurityRadarVerdict{
				{ModuleID: "verified_arm", Module: "Verified arm", Signed: true, Signature: "sig-arm", Signals: map[string]any{"evidence_status": "verified"}, Evidence: []string{"account:one"}},
				{ModuleID: "observed_arm", Module: "Observed arm", Signed: true, Signals: map[string]any{"evidence_status": "observed"}, Evidence: []string{"observation:one"}},
				{ModuleID: "pending_arm", Module: "Pending arm", Verdict: "Live source did not complete.", Signals: map[string]any{"execution_status": "evidence_pending"}},
				{ModuleID: "not_applicable_arm", Module: "Not applicable arm", Recommendation: "not_applicable", Signals: map[string]any{"applicable": false}},
			},
		},
		UnifiedVerdict: services.UnifiedRadarVerdict{
			Grade:          "C",
			Verdict:        "severe_compounding_rule",
			RulesetVersion: "rules-v1",
			ActorRuleset:   "actor-v1",
			Signed:         true,
			Signature:      "signed-verdict",
			DecisionPath:   []string{"Rule URD-C002 triggered.", "Rule URD-C004 triggered."},
			TriggeredRules: []services.ActorDefenseRuleHit{
				{RuleID: "URD-C002", Title: "Holder pressure", Tier: "compounding", EvidenceStatus: "observed", GradeEffect: "compounding_input", Summary: "Dominant holder position exceeds observed liquidity.", EvidenceKeys: []string{"holder-liquidity:Mint111"}},
			},
			WatchFlags: []services.ActorDefenseRuleHit{
				{RuleID: "ARD-W001", Title: "Inferred relationship", Tier: "watch", EvidenceStatus: "inferred", GradeEffect: "watch_only", Summary: "Relationship requires verification."},
			},
		},
		Behavior: services.UnifiedRadarBehaviorReport{Signals: []services.UnifiedRadarSignal{
			{RuleID: "URD-C001", Title: "Volume/liquidity gap", EvidenceStatus: "observed", Triggered: false, Summary: "Observed ratio stayed below the explicit threshold.", ObservedAt: time.Now().UTC()},
			{RuleID: "URD-C003", Title: "Creator sell acceleration", EvidenceStatus: "unverified", Triggered: false, Summary: "Creator trade history is unavailable."},
		}},
	}

	summary := buildCustomerAnalysisSummary(assembly, true)
	if summary["schema_version"] != customerAnalysisSummarySchemaVersion {
		t.Fatalf("schema_version=%v", summary["schema_version"])
	}
	decision := summary["decision"].(map[string]any)
	if decision["grade"] != "C" || decision["confidence"] != "medium" || decision["readiness"] != "actionable_with_gaps" {
		t.Fatalf("unexpected decision summary: %#v", decision)
	}
	coverage := summary["evidence_coverage"].(map[string]any)
	if coverage["architecture_arm_count"] != 14 || coverage["verified"] != 1 || coverage["observed"] != 1 || coverage["not_applicable"] != 1 || coverage["pending"] != 11 {
		t.Fatalf("unexpected evidence coverage: %#v", coverage)
	}
	if coverage["coverage_is_risk_score"] != false {
		t.Fatalf("coverage must not be represented as a risk score: %#v", coverage)
	}
	findings := summary["grade_changing_findings"].([]map[string]any)
	if len(findings) != 1 || findings[0]["rule_id"] != "URD-C002" || findings[0]["severity"] != "high" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	watch := summary["watch_items"].([]map[string]any)
	if len(watch) != 1 || watch[0]["grade_effect"] != "watch_only" {
		t.Fatalf("unexpected watch items: %#v", watch)
	}
	nonTriggered := summary["non_triggered_observations"].([]map[string]any)
	if len(nonTriggered) != 1 || nonTriggered[0]["rule_id"] != "URD-C001" {
		t.Fatalf("unexpected non-triggered observations: %#v", nonTriggered)
	}
	unresolved := summary["unresolved_questions"].([]map[string]any)
	if len(unresolved) < 3 {
		t.Fatalf("expected pending arm, unverified rule and architecture gap: %#v", unresolved)
	}
	actions := summary["recommended_actions"].([]map[string]any)
	if len(actions) < 3 {
		t.Fatalf("expected evidence review, gap closure and watch actions: %#v", actions)
	}
	if text, _ := summary["executive_summary"].(string); !strings.Contains(text, "signed deterministic C verdict") {
		t.Fatalf("unexpected executive summary: %q", text)
	}
	if _, exists := summary["risk_score"]; exists {
		t.Fatal("advanced summary must not invent a numeric risk score")
	}
}

func TestCustomerAnalysisSummaryUnsignedIsExplicitlyLowConfidence(t *testing.T) {
	assembly := unifiedInvestigationAssembly{
		Core: holderIntelligenceCoreResult{Request: services.SecurityRadarRequest{Target: "Mint222", Network: "solana-mainnet"}},
		UnifiedVerdict: services.UnifiedRadarVerdict{Grade: "-", Verdict: "watch_only", Signed: false},
	}
	summary := buildCustomerAnalysisSummary(assembly, false)
	decision := summary["decision"].(map[string]any)
	if decision["confidence"] != "low" || decision["readiness"] != "evidence_pending" {
		t.Fatalf("unexpected unsigned decision: %#v", decision)
	}
	if text := summary["executive_summary"].(string); !strings.Contains(text, "No signed letter grade was issued") || !strings.Contains(text, "missing evidence is not a positive safety signal") {
		t.Fatalf("unsigned summary did not preserve evidence policy: %q", text)
	}
	actions := summary["recommended_actions"].([]map[string]any)
	foundUnsignedWarning := false
	for _, action := range actions {
		if strings.Contains(strings.ToLower(action["action"].(string)), "unsigned result") {
			foundUnsignedWarning = true
			break
		}
	}
	if !foundUnsignedWarning {
		t.Fatalf("unsigned result warning missing: %#v", actions)
	}
}

func TestCustomerInvestigationEnvelopeEmbedsAdvancedSummaryAtBothLevels(t *testing.T) {
	assembly := unifiedInvestigationAssembly{
		Report: map[string]any{"ok": true, "schema_version": unifiedInvestigationSchemaVersion},
		Core: holderIntelligenceCoreResult{Request: services.SecurityRadarRequest{Target: "Mint333", Network: "solana-mainnet"}},
		UnifiedVerdict: services.UnifiedRadarVerdict{Grade: "-", Verdict: "no_grade_trigger", Signed: false},
	}
	envelope := customerInvestigationEnvelope(assembly, false)
	if envelope["response_schema_version"] != customerInvestigationResponseSchemaVersion {
		t.Fatalf("response schema missing: %#v", envelope)
	}
	topSummary, ok := envelope["analysis_summary"].(map[string]any)
	if !ok || topSummary["schema_version"] != customerAnalysisSummarySchemaVersion {
		t.Fatalf("top-level analysis summary missing: %#v", envelope["analysis_summary"])
	}
	report := envelope["investigation_report"].(map[string]any)
	reportSummary, ok := report["analysis_summary"].(map[string]any)
	if !ok || reportSummary["schema_version"] != customerAnalysisSummarySchemaVersion {
		t.Fatalf("report analysis summary missing: %#v", report["analysis_summary"])
	}
}
