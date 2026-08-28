package handlers

import (
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestCanonicalVerdictSynchronizationRunsBeforeSnapshotDiagnostics(t *testing.T) {
	actor := services.ActorDefenseRuleVerdict{
		RulesetVersion: services.ActorDefenseRulesetVersion,
		TriggeredRules: repeatedTransferGroupsV111(4),
		WatchFlags:     []services.ActorDefenseRuleHit{},
	}
	behavior := ownerConcentrationBehaviorV111()
	report := map[string]any{
		"target":  "MintSync111",
		"network": "solana-mainnet",
		"final_verdict": services.UnifiedRadarVerdict{
			Grade:          "B",
			Verdict:        "compounding_rule",
			Signed:         true,
			Signature:      "stale-b",
			RulesetVersion: "koschei-unified-radar-rules-v1.1.0",
		},
		"actor_investigation": map[string]any{"rule_verdict": actor},
		"behavior_signals":    behavior,
	}

	attachFinalProductIntegrationDiagnostics(report)
	var final services.UnifiedRadarVerdict
	if !decodeCanonicalVerdictValue(report["final_verdict"], &final) {
		t.Fatal("synchronized final verdict missing")
	}
	if final.Grade != "F" || final.Verdict != "hard_trigger" || !final.Signed || final.RulesetVersion != services.UnifiedRadarRulesetVersionV110 || final.Signature == "stale-b" {
		t.Fatalf("stale verdict survived pre-snapshot synchronization: %#v", final)
	}
	decisionPath := strings.Join(final.DecisionPath, "\n")
	if strings.Contains(decisionPath, "5 distinct") || !strings.Contains(decisionPath, "only one distinct compounding rule ID") {
		t.Fatalf("incorrect synchronized decision path: %s", decisionPath)
	}
}

func TestCustomerAnalysisSummaryV3SeparatesDeterminingAndSupportingFindings(t *testing.T) {
	actor := services.ActorDefenseRuleVerdict{
		RulesetVersion: services.ActorDefenseRulesetVersion,
		TriggeredRules: repeatedTransferGroupsV111(4),
		WatchFlags:     []services.ActorDefenseRuleHit{},
	}
	behavior := ownerConcentrationBehaviorV111()
	final := services.EvaluateUnifiedRadarVerdictV110("MintSummary111", actor, behavior)
	summary := buildCustomerAnalysisSummaryV3(unifiedInvestigationAssembly{
		UnifiedVerdict: final,
		Behavior:       behavior,
	}, true)

	if summary["schema_version"] != customerAnalysisSummarySchemaVersionV3 {
		t.Fatalf("summary schema=%v", summary["schema_version"])
	}
	determining, _ := summary["grade_changing_findings"].([]map[string]any)
	supporting, _ := summary["supporting_findings"].([]map[string]any)
	groups, _ := summary["triggered_evidence_groups"].([]map[string]any)
	decision, _ := summary["decision"].(map[string]any)
	if len(determining) != 1 || determining[0]["rule_id"] != services.UnifiedRuleOwnerConcentration || len(supporting) != 4 || len(groups) != 5 {
		t.Fatalf("v3 classification incorrect: determining=%#v supporting=%#v groups=%#v", determining, supporting, groups)
	}
	if decision["grade_determining_rule_count"] != 1 || decision["distinct_compounding_rule_count"] != 1 || decision["triggered_evidence_group_count"] != 5 {
		t.Fatalf("v3 decision counts=%#v", decision)
	}
}

func repeatedTransferGroupsV111(count int) []services.ActorDefenseRuleHit {
	groups := make([]services.ActorDefenseRuleHit, 0, count)
	for i := 0; i < count; i++ {
		groups = append(groups, services.ActorDefenseRuleHit{
			RuleID:         services.ActorRuleCompoundRepeatedTransfer,
			Title:          "Repeated direct transfer relation",
			Tier:           "compounding",
			EvidenceStatus: "verified",
			GradeEffect:    "compounding_input",
			Count:          i + 2,
			Summary:        "separate evidence group from the same deterministic rule",
			EvidenceKeys:   []string{"evidence-key"},
			Signatures:     []string{"signature"},
		})
	}
	return groups
}

func ownerConcentrationBehaviorV111() services.UnifiedRadarBehaviorReport {
	return services.UnifiedRadarBehaviorReport{
		RulesetVersion: services.UnifiedRadarRulesetVersionV110,
		Signals: []services.UnifiedRadarSignal{
			{
				RuleID:         services.UnifiedRuleOwnerConcentration,
				Title:          "Owner-resolved dominant concentration",
				EvidenceStatus: "verified",
				Triggered:      true,
				GradeEffect:    "hard_cap_F",
				Scope:          "owner_resolved_infrastructure_excluded_circulating_supply",
				Summary:        "Owner-resolved top ownership met the F-cap threshold.",
				Metrics:        map[string]any{"owner_resolved_top_share_pct": 99.2987},
				Thresholds:     map[string]any{"f_cap_pct": 70.0},
				EvidenceKeys:   []string{"owner:dominant"},
				Signatures:     []string{},
				Limitations:    []string{},
				ObservedAt:     time.Now().UTC(),
			},
		},
		GeneratedAt: time.Now().UTC(),
	}
}
