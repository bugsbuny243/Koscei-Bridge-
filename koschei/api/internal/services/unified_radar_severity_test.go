package services

import (
	"strings"
	"testing"
)

func TestUnifiedVerdictCapsSevereHolderLiquidityExitAtC(t *testing.T) {
	behavior := UnifiedRadarBehaviorReport{Signals: []UnifiedRadarSignal{
		{
			RuleID:         UnifiedRuleHolderLiquidityPressure,
			Title:          "Dominant-holder position / liquidity depth",
			EvidenceStatus: "observed",
			Triggered:      true,
			GradeEffect:    "compounding_input",
			Metrics:        map[string]any{"position_liquidity_ratio": 49.17},
			Summary:        "Dominant-holder reference position equals 49.17x reported liquidity.",
		},
		{
			RuleID:         UnifiedRuleDominantHolderFirstExit,
			Title:          "Dominant-holder first observed exit",
			EvidenceStatus: "verified",
			Triggered:      true,
			GradeEffect:    "compounding_input",
			Metrics:        map[string]any{"amount": 1000.0, "destination": "PoolOne"},
			Summary:        "A transaction-backed dominant-holder exit was observed.",
		},
	}}

	verdict := EvaluateUnifiedRadarVerdict("MintOne", ActorDefenseRuleVerdict{}, behavior)
	if verdict.Grade != "C" || verdict.Verdict != "severe_compounding_rule" || !verdict.Signed {
		t.Fatalf("severity-aware verdict=%#v", verdict)
	}
	decision := strings.Join(verdict.DecisionPath, " ")
	if !strings.Contains(decision, UnifiedRuleHolderLiquidityPressure) ||
		!strings.Contains(decision, UnifiedRuleDominantHolderFirstExit) ||
		!strings.Contains(decision, "49.17x") {
		t.Fatalf("decision path does not expose rule facts: %q", decision)
	}
}
