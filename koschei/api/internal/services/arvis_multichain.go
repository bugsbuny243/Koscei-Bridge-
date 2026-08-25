package services

import (
	"context"
	"strings"
)

// AnalyzeArvisRadarsMultiChainContext is the chain-dispatch boundary for ARVIS.
// Public Pi targets default to Pi mainnet; testnet remains explicit. Existing
// Solana targets continue through the mature Solana collector unchanged. Pi
// external provenance and issuer-control interpretations are layered after the
// on-chain snapshot so those evidence classes cannot be confused with transport.
func AnalyzeArvisRadarsMultiChainContext(ctx context.Context, req SecurityRadarRequest) ArvisAnalysis {
	req.Target = strings.TrimSpace(req.Target)
	req.Network = strings.TrimSpace(req.Network)

	if piTarget, ok := ParsePiRadarTarget(req.Target); ok {
		if req.Network == "" {
			req.Network = DefaultPiRadarNetwork()
		} else if normalized, piNetwork := NormalizePiRadarNetwork(req.Network); piNetwork {
			req.Network = normalized
		} else {
			return piNetworkMismatchAnalysis(req)
		}
		analysis := analyzePiArvisRadarsNetworkContext(ctx, req, piTarget)
		analysis = enrichPiIssuerControlEvidence(analysis, piTarget)
		return enrichPiDomainBindingEvidence(ctx, analysis, piTarget)
	}

	if normalized, piNetwork := NormalizePiRadarNetwork(req.Network); piNetwork {
		req.Network = normalized
		return piInvalidTargetAnalysis(req)
	}
	return AnalyzeArvisRadarsContext(ctx, req)
}

func AnalyzeArvisRadarsMultiChain(req SecurityRadarRequest) ArvisAnalysis {
	return AnalyzeArvisRadarsMultiChainContext(context.Background(), req)
}

func piInvalidTargetAnalysis(req SecurityRadarRequest) ArvisAnalysis {
	network, ok := NormalizePiRadarNetwork(req.Network)
	if !ok {
		network = DefaultPiRadarNetwork()
	}
	req.Network = network
	if req.Mode == "" {
		req.Mode = SecurityRadarWatchMode
	}
	final := SecurityRadarFinalVerdict{Grade: "-", RiskIndex: 0, RiskLevel: "unknown", Verdict: "Pi target format could not be verified; no evidence collection or risk grade was performed.", Recommendation: "provide_pi_public_account_or_asset", RuleVersion: piArvisNetworkEvidenceRuleset, Signed: false}
	return ArvisAnalysis{Bundle: SecurityRadarBundle{Target: req.Target, Network: network, Provider: PiRadarEvidenceSourceForNetwork(network), WatchMode: req.Mode, CustomerSummary: final.Verdict, CustomerRecommendation: final.Recommendation, Metadata: map[string]any{"chain": "pi", "chain_adapter": "pi_horizon_v2", "network": network, "evidence_status": "invalid_target", "signed_grade_enabled": false, "unknown_is_not_safe": true}}, Arms: []SecurityRadarVerdict{}, Final: final}
}

func piNetworkMismatchAnalysis(req SecurityRadarRequest) ArvisAnalysis {
	if req.Mode == "" {
		req.Mode = SecurityRadarWatchMode
	}
	final := SecurityRadarFinalVerdict{Grade: "-", RiskIndex: 0, RiskLevel: "unknown", Verdict: "The supplied target is a Pi target but the requested network is not a Pi network; no cross-chain reinterpretation was performed.", Recommendation: "select_pi_mainnet_or_pi_testnet", RuleVersion: piArvisNetworkEvidenceRuleset, Signed: false}
	return ArvisAnalysis{Bundle: SecurityRadarBundle{Target: req.Target, Network: req.Network, Provider: "none", WatchMode: req.Mode, CustomerSummary: final.Verdict, CustomerRecommendation: final.Recommendation, Metadata: map[string]any{"chain": "pi", "chain_adapter": "pi_horizon_v2", "requested_network": req.Network, "evidence_status": "network_mismatch", "signed_grade_enabled": false, "unknown_is_not_safe": true}}, Arms: []SecurityRadarVerdict{}, Final: final}
}
