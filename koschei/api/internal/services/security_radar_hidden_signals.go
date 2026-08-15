package services

import "context"

const sbx1HiddenSignalRuleVersion = "sbx1-hidden-risk-signals-retired"

type sbx1HiddenSignalPack struct {
	Signals        map[string]any
	RiskAdjustment int
}

// Hidden SBX-1 risk-score adjustments are retired. Stream observations are
// evidence only; the canonical unified evaluator is the sole grade/verdict
// authority. These compatibility helpers remain temporarily so older store
// call sites cannot mutate a verdict while the legacy persistence layer is
// being removed.
func shouldApplySBX1HiddenSignals(SecurityRadarVerdictRecord) bool { return false }

func buildSBX1HiddenSignalPack(_ context.Context, _ SecurityRadarVerdictRecord) sbx1HiddenSignalPack {
	return sbx1HiddenSignalPack{
		Signals: map[string]any{
			"status":           "retired",
			"customer_surface": false,
			"visibility":       "internal_only",
			"rule_version":     sbx1HiddenSignalRuleVersion,
			"purpose":          "legacy_hidden_risk_adjustment_retired",
		},
		RiskAdjustment: 0,
	}
}

func sbx1HiddenTargetType(SecurityRadarVerdictRecord) string { return "retired" }
func hiddenRiskAdjustment(int) int                           { return 0 }
func applyHiddenRiskAdjustment(_ *SecurityRadarVerdictRecord, _ int) {}
