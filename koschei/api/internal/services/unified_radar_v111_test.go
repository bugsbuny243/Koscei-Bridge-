package services

import (
	"strings"
	"testing"
	"time"
)

func TestUnifiedRadarV111CountsDistinctCompoundingRuleIDs(t *testing.T) {
	hits := []ActorDefenseRuleHit{}
	for i := 0; i < 4; i++ {
		hits = append(hits, ActorDefenseRuleHit{
			RuleID:         ActorRuleCompoundRepeatedTransfer,
			Title:          "Repeated direct transfer relation",
			Tier:           "compounding",
			EvidenceStatus: "verified",
			GradeEffect:    "compounding_input",
			Count:          i + 2,
			Summary:        "A separate evidence group from the same deterministic rule.",
			EvidenceKeys:   []string{"evidence-group"},
			Signatures:     []string{"signature-group"},
		})
	}
	actor := ActorDefenseRuleVerdict{
		Grade:          "B",
		Verdict:        "compounding_rule",
		RulesetVersion: ActorDefenseRulesetVersion,
		TriggeredRules: hits,
		WatchFlags:     []ActorDefenseRuleHit{},
	}
	behavior := UnifiedRadarBehaviorReport{
		RulesetVersion: UnifiedRadarRulesetVersionV110,
		Signals: []UnifiedRadarSignal{
			{
				RuleID:         UnifiedRuleOwnerConcentration,
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

	verdict := EvaluateUnifiedRadarVerdictV110("Mint111", actor, behavior)
	if verdict.Grade != "F" || verdict.Verdict != "hard_trigger" || !verdict.Signed {
		t.Fatalf("unexpected corrected verdict: %#v", verdict)
	}
	if verdict.RulesetVersion != "koschei-unified-radar-rules-v1.1.1" {
		t.Fatalf("ruleset=%q", verdict.RulesetVersion)
	}
	if len(verdict.TriggeredRules) != 5 {
		t.Fatalf("audit evidence groups must remain visible, got %d", len(verdict.TriggeredRules))
	}
	joined := strings.Join(verdict.DecisionPath, "\n")
	if strings.Contains(joined, "5 distinct") || strings.Contains(joined, "lowered the baseline by one grade to B") {
		t.Fatalf("decision path retained evidence-group overcount: %s", joined)
	}
	if !strings.Contains(joined, "only one distinct compounding rule ID") || !strings.Contains(joined, "URD-C005 fixed the maximum grade at F") {
		t.Fatalf("correct deterministic explanation missing: %s", joined)
	}
}

func TestUnifiedRadarV111TwoDistinctRulesMayCompound(t *testing.T) {
	actor := ActorDefenseRuleVerdict{
		RulesetVersion: ActorDefenseRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{
			{RuleID: ActorRuleCompoundCreatorReuse, Tier: "compounding", EvidenceStatus: "verified", GradeEffect: "compounding_input", Summary: "creator reused"},
			{RuleID: ActorRuleCompoundHolderReuse, Tier: "compounding", EvidenceStatus: "observed", GradeEffect: "compounding_input", Summary: "holder reused"},
		},
		WatchFlags: []ActorDefenseRuleHit{},
	}
	behavior := UnifiedRadarBehaviorReport{Signals: []UnifiedRadarSignal{}, GeneratedAt: time.Now().UTC()}
	verdict := EvaluateUnifiedRadarVerdictV110("Mint222", actor, behavior)
	if verdict.Grade != "B" || verdict.Verdict != "compounding_rule" || !verdict.Signed {
		t.Fatalf("two distinct compounding rules did not produce B: %#v", verdict)
	}
}
