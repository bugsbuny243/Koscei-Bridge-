package services

import (
	"context"
	"strings"
)

// AnalyzeArvisRadarsMultiChainContext is the chain-dispatch boundary for ARVIS.
// Pi targets are routed to the Pi Testnet evidence adapter; existing Solana
// targets continue through the mature Solana collector unchanged. Pi external
// provenance, issuer-control, liquidity-history and holder-funding evidence are
// layered after the base Horizon snapshot so each evidence class remains explicit.
func AnalyzeArvisRadarsMultiChainContext(ctx context.Context, req SecurityRadarRequest) ArvisAnalysis {
	req.Target = strings.TrimSpace(req.Target)
	req.Network = strings.TrimSpace(req.Network)
	if piTarget, ok := ParsePiRadarTarget(req.Target); ok && (req.Network == "" || IsPiRadarNetwork(req.Network)) {
		analysis := analyzePiArvisRadarsContext(ctx, req, piTarget)
		analysis = enrichPiIssuerControlEvidence(analysis, piTarget)
		analysis = enrichPiLiquidityHistoryEvidence(ctx, analysis, piTarget)
		analysis = enrichPiFundingClusterEvidenceFromHorizon(ctx, analysis, piTarget)
		analysis = enrichPiDomainBindingEvidence(ctx, analysis, piTarget)
		return refreshPiAnalysisEvidenceMetadata(analysis)
	}
	if IsPiRadarNetwork(req.Network) {
		return piInvalidTargetAnalysis(req)
	}
	return AnalyzeArvisRadarsContext(ctx, req)
}

func AnalyzeArvisRadarsMultiChain(req SecurityRadarRequest) ArvisAnalysis {
	return AnalyzeArvisRadarsMultiChainContext(context.Background(), req)
}

func piInvalidTargetAnalysis(req SecurityRadarRequest) ArvisAnalysis {
	req.Network = piTestnetNetwork
	if req.Mode == "" {
		req.Mode = SecurityRadarWatchMode
	}
	final := SecurityRadarFinalVerdict{Grade: "-", RiskIndex: 0, RiskLevel: "unknown", Verdict: "Pi target format could not be verified; no evidence collection or risk grade was performed.", Recommendation: "provide_pi_public_account_or_asset", RuleVersion: piArvisEvidenceRuleset, Signed: false}
	return ArvisAnalysis{Bundle: SecurityRadarBundle{Target: req.Target, Network: req.Network, Provider: piRadarEvidenceSourceHorizon, WatchMode: req.Mode, CustomerSummary: final.Verdict, CustomerRecommendation: final.Recommendation, Metadata: map[string]any{"chain_adapter": "pi_horizon_v1", "evidence_status": "invalid_target", "signed_grade_enabled": false, "unknown_is_not_safe": true}}, Arms: []SecurityRadarVerdict{}, Final: final}
}
