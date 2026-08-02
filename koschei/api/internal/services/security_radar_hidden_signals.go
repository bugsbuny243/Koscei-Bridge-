package services

import (
	"context"
	"strings"
	"time"
)

const (
	sbx1HiddenSignalRuleVersion = "sbx1-hidden-risk-signals-v1"
)

type sbx1HiddenSignalPack struct {
	Signals        map[string]any
	RiskAdjustment int
}

func shouldApplySBX1HiddenSignals(verdict SecurityRadarVerdictRecord) bool {
	if !strings.EqualFold(strings.TrimSpace(verdict.Source), "sbx1_stream") {
		return false
	}
	if strings.TrimSpace(verdict.Target) == "" {
		return false
	}
	if verdict.ModuleID != ModulePumpSybilRadar && verdict.ModuleID != ModuleRaydiumPoolGuardian {
		return false
	}
	return true
}

func buildSBX1HiddenSignalPack(ctx context.Context, verdict SecurityRadarVerdictRecord) sbx1HiddenSignalPack {
	out := sbx1HiddenSignalPack{Signals: map[string]any{
		"customer_surface": false,
		"visibility":       "internal_only",
		"rule_version":     sbx1HiddenSignalRuleVersion,
		"purpose":          "legacy risk-score modules embedded as hidden SBX-1 backend signals",
	}}
	if !shouldApplySBX1HiddenSignals(verdict) {
		out.Signals["status"] = "skipped"
		return out
	}

	targetType := sbx1HiddenTargetType(verdict)
	moduleCtx, cancel := context.WithTimeout(ctx, 4500*time.Millisecond)
	defer cancel()

	engine := NewUnifiedEngine(nil)
	result, err := engine.Analyze(moduleCtx, UnifiedAnalyzeRequest{TargetType: targetType, TargetID: verdict.Target, Network: firstRadarValue(verdict.Network, "solana-mainnet"), Notes: "SBX-1 hidden internal signal pass"})
	if err != nil {
		out.Signals["status"] = "error"
		out.Signals["error"] = compactRadarError("unified_hidden_engine", err)
		return out
	}

	modules := map[string]any{}
	maxHiddenRisk := 0
	okCount := 0
	for name, module := range result.ModuleResults {
		entry := map[string]any{
			"status":      module.Status,
			"score":       module.Score,
			"risk_level":  module.RiskLevel,
			"summary":     module.Summary,
			"duration_ms": module.DurationMS,
		}
		if len(module.Findings) > 0 {
			entry["primary_finding"] = module.Findings[0]
		}
		modules[name] = entry
		if module.Status == "ok" {
			okCount++
			risk := 100 - module.Score
			if risk > maxHiddenRisk {
				maxHiddenRisk = risk
			}
		}
	}

	out.RiskAdjustment = hiddenRiskAdjustment(maxHiddenRisk)
	out.Signals["status"] = "ok"
	out.Signals["target_type"] = targetType
	out.Signals["overall_score"] = result.OverallScore
	out.Signals["overall_risk_level"] = result.RiskLevel
	out.Signals["partial_success"] = result.PartialSuccess
	out.Signals["module_count"] = len(result.ModuleResults)
	out.Signals["ok_module_count"] = okCount
	out.Signals["max_hidden_risk_index"] = maxHiddenRisk
	out.Signals["risk_adjustment"] = out.RiskAdjustment
	out.Signals["modules"] = modules
	return out
}

func sbx1HiddenTargetType(verdict SecurityRadarVerdictRecord) string {
	targetType := strings.ToLower(strings.TrimSpace(verdict.TargetType))
	target := strings.TrimSpace(verdict.Target)
	if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
		return "url"
	}
	if targetType == "token" || targetType == "token_or_launch" || targetType == "pool_or_token" || strings.Contains(targetType, "token") || strings.Contains(targetType, "mint") {
		return "mint"
	}
	if len(target) >= 80 {
		return "tx"
	}
	if targetType == "wallet" || targetType == "address" {
		return "address"
	}
	return "address"
}

func hiddenRiskAdjustment(maxHiddenRisk int) int {
	switch {
	case maxHiddenRisk >= 75:
		return 18
	case maxHiddenRisk >= 60:
		return 12
	case maxHiddenRisk >= 40:
		return 7
	case maxHiddenRisk >= 25:
		return 3
	default:
		return 0
	}
}

func applyHiddenRiskAdjustment(verdict *SecurityRadarVerdictRecord, adjustment int) {
	if verdict == nil || adjustment <= 0 {
		return
	}
	verdict.RiskIndex = clampRisk(verdict.RiskIndex + adjustment)
	verdict.RiskLevel = riskLevelFromIndex(verdict.RiskIndex)
	verdict.Grade = gradeFromRiskLevel(verdict.RiskLevel)
	verdict.Recommendation = recommendationFromRiskLevel(verdict.RiskLevel)
	verdict.Verdict = verdictFromRiskLevel(verdict.ModuleID, verdict.RiskLevel, nonNilMap(verdict.Signals))
	if verdict.Signature != "" {
		verdict.Signature = signSecurityRadarVerdict(verdict.ModuleID, verdict.Target, verdict.Network, verdict.RiskIndex)
	}
}
