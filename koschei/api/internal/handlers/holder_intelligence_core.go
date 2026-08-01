package handlers

import (
	"context"
	"strings"
	"time"

	"koschei/api/internal/services"
	"koschei/api/internal/web3"
)

type holderIntelligenceCoreResult struct {
	Request               services.SecurityRadarRequest
	Analysis              services.ArvisAnalysis
	Bundle                services.SecurityRadarBundle
	Arms                  []services.SecurityRadarVerdict
	Final                 services.SecurityRadarFinalVerdict
	Roles                 services.HolderRoleAnalysis
	Distribution          map[string]any
	Cluster               services.HolderClusterAnalysis
	Market                services.TokenMarketSnapshot
	Intelligence          services.HolderIntelligence
	LaunchForensics       services.LaunchForensicsAnalysis
	LPControl             services.LPControlEvidence
	JupiterContext        services.JupiterMarketContext
	ExitLiquidity         services.ExitLiquiditySimulation
	RepeatDominantHolders []services.RepeatDominantHolderEvidence
	ThreatAnticipation    services.ThreatAnticipationReport
	SourceContext         map[string]any
}

func (h *Handler) runHolderIntelligenceCore(parent context.Context, target, network, mode string) holderIntelligenceCoreResult {
	if parent == nil {
		parent = context.Background()
	}
	target = strings.TrimSpace(target)
	network = strings.TrimSpace(network)
	if network == "" {
		network = "solana-mainnet"
	}
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "manual_detail"
	}

	req := services.SecurityRadarRequest{Target: target, Network: network, Mode: mode}
	analysis := services.AnalyzeArvisRadarsContext(parent, req)
	bundle := services.EvidenceBackedSecurityRadarBundle(analysis.Bundle)
	roles := services.ArvisHolderRolesFromBundle(bundle)
	distribution := radarDetailHolderDistributionFromRoles(roles)
	if !roles.Available {
		distribution, roles = radarDetailHolderDistribution(parent, target)
	}
	cluster := services.ArvisHolderClusterFromBundle(bundle)
	source := h.radarDetailSourceContext(parent, target, network)
	source = h.resolveCanonicalCreatorSourceContext(parent, target, network, mode, source)
	launch := h.analyzeLaunchForensics(parent, target, roles, cluster, source)
	analysis = services.ApplyLaunchForensicsToAnalysis(analysis, req, launch)
	market := radarDetailMarketSnapshot(parent, target)
	creator := strings.TrimSpace(creatorIntelCleanString(source["creator_wallet"]))
	analysis = services.ApplyCreatorAndLiquidityEvidenceToAnalysis(analysis, req, creator, market, launch)
	bundle = services.EvidenceBackedSecurityRadarBundle(analysis.Bundle)
	arms := services.ArvisArmsFromBundle(bundle)
	if len(arms) == 0 {
		arms = analysis.Arms
	}
	final := services.ArvisFinalFromBundle(bundle)
	intelligence := services.ApplyLaunchForensicsToHolderIntelligence(services.BuildHolderIntelligence(roles, cluster, market, time.Now().UTC()), launch)
	repeatDominant := []services.RepeatDominantHolderEvidence{}
	if h != nil {
		historyDB := h.DB
		if historyDB == nil {
			historyDB = h.DBRead
		}
		if historyDB != nil {
			store := services.NewSecurityRadarStore(historyDB)
			_ = store.CaptureHolderSnapshots(parent, target, network, intelligence)
			if found, err := store.RepeatDominantHolders(parent, intelligence, target, services.RepeatDominantObservationDays); err == nil {
				repeatDominant = found
				if len(found) > 0 {
					intelligence = services.ApplyRepeatDominantHolderEvidenceToHolderIntelligence(intelligence, found)
				}
				analysis = services.ApplyRepeatDominantHolderEvidenceToAnalysis(analysis, req, found)
				bundle = services.EvidenceBackedSecurityRadarBundle(analysis.Bundle)
				arms = services.ArvisArmsFromBundle(bundle)
				if len(arms) == 0 {
					arms = analysis.Arms
				}
				final = services.ArvisFinalFromBundle(bundle)
			}
		}
	}

	lpControl := services.LPControlEvidence{Status: "not_requested_preflight", ObservedAt: time.Now().UTC(), LargestLPHolders: []services.LPHolderEvidence{}, EvidenceKeys: []string{}, Limitations: []string{}}
	jupiter := services.JupiterMarketContext{Status: "not_requested_preflight", RouteLabels: []string{}, Limitations: []string{}}
	exitLiquidity := services.ExitLiquiditySimulation{
		Status: "not_requested_preflight", Provider: "jupiter_quote", Mint: target,
		OutputMint: jupiterUSDCMint, QuoteOnly: true, Tiers: []services.ExitLiquidityTier{},
		ObservedAt: time.Now().UTC(), Limitations: []string{},
	}
	programSecurity := newProgramSecuritySurface("not_requested_preflight")
	if phase2MarketContextAllowed(mode) && h != nil {
		lpControl = h.collectCompleteLPControlEvidence(parent, network, target, creator, market, source)
		analysis = services.ApplyLPControlEvidenceToAnalysis(analysis, req, lpControl)
		bundle = services.EvidenceBackedSecurityRadarBundle(analysis.Bundle)
		arms = services.ArvisArmsFromBundle(bundle)
		if len(arms) == 0 {
			arms = analysis.Arms
		}
		final = services.ArvisFinalFromBundle(bundle)
		jupiter = h.collectJupiterMarketContext(parent, network, target, intelligence, market)
		exitLiquidity = h.collectExitLiquiditySimulation(parent, network, target, market, jupiter)
		jupiter.ExitLiquidity = exitLiquidity
		programSecurity = h.collectProgramSecuritySurface(parent, network, source, lpControl, market)
	}
	if source == nil {
		source = map[string]any{}
	}
	source["program_security"] = programSecurity
	if h != nil && h.DB != nil {
		services.NewSecurityRadarStore(h.DB).CaptureLaunchForensicsFloor(parent, target, network, launch)
	}
	threatAnticipation := services.BuildThreatAnticipation(services.ThreatAnticipationInput{Target: target, Market: market, Holder: intelligence, Cluster: cluster, Arms: arms})
	return holderIntelligenceCoreResult{Request: req, Analysis: analysis, Bundle: bundle, Arms: arms, Final: final, Roles: roles, Distribution: distribution, Cluster: cluster, Market: market, Intelligence: intelligence, LaunchForensics: launch, LPControl: lpControl, JupiterContext: jupiter, ExitLiquidity: exitLiquidity, RepeatDominantHolders: repeatDominant, ThreatAnticipation: threatAnticipation, SourceContext: source}
}

func phase2MarketContextAllowed(mode string) bool {
	value := strings.ToLower(strings.TrimSpace(mode))
	return !strings.Contains(value, "preflight") && !strings.Contains(value, "safe_check") && !strings.Contains(value, "safe-check")
}
func holderIntelligenceCoreConcentration(core holderIntelligenceCoreResult) (float64, float64, bool) {
	if core.Intelligence.Available && core.Intelligence.CirculatingSupply > 0 {
		return core.Intelligence.Top1Percentage, core.Intelligence.Top10Percentage, true
	}
	if core.Roles.Available && core.Roles.CirculatingSupply > 0 {
		return core.Roles.EffectiveTop1Percentage, core.Roles.EffectiveTop10Percentage, true
	}
	return 0, 0, false
}
func holderIntelligenceCoreStatus(core holderIntelligenceCoreResult) string {
	if strings.TrimSpace(core.Intelligence.Status) != "" {
		return core.Intelligence.Status
	}
	if strings.TrimSpace(core.Roles.Status) != "" {
		return core.Roles.Status
	}
	return "holder_data_unavailable"
}
func holderIntelligenceCorePolicy(core holderIntelligenceCoreResult) string {
	if !core.Intelligence.Available || core.Intelligence.FinalVerdictBlocked || core.Roles.BlockingEvidenceGap {
		return "withhold"
	}
	return "evidence_backed"
}
func holderIntelligenceCoreRepeatRisk(core holderIntelligenceCoreResult) int {
	strongest := 0
	for _, item := range core.RepeatDominantHolders {
		if item.RiskWeight > strongest {
			strongest = item.RiskWeight
		}
	}
	return strongest
}
func applyRepeatDominantRiskToLegacyScore(score int, _ holderIntelligenceCoreResult) int { return score }
func holderIntelligenceCoreEvidence(core holderIntelligenceCoreResult) []string {
	values := []string{}
	values = appendUniqueHolderCoreEvidence(values, core.Intelligence.Findings...)
	values = appendUniqueHolderCoreEvidence(values, core.Cluster.Findings...)
	values = appendUniqueHolderCoreEvidence(values, core.LaunchForensics.Findings...)
	for _, repeat := range core.RepeatDominantHolders {
		values = appendUniqueHolderCoreEvidence(values, repeat.EvidenceLine)
	}
	if strings.TrimSpace(core.LaunchForensics.Summary) != "" {
		values = appendUniqueHolderCoreEvidence(values, core.LaunchForensics.Summary)
	}
	for _, limitation := range core.Intelligence.Limitations {
		values = appendUniqueHolderCoreEvidence(values, "LIMITATION: "+limitation)
	}
	for _, limitation := range core.LaunchForensics.Limitations {
		values = appendUniqueHolderCoreEvidence(values, "LIMITATION: "+limitation)
	}
	return values
}
func appendUniqueHolderCoreEvidence(dst []string, values ...string) []string {
	seen := map[string]bool{}
	for _, value := range dst {
		seen[strings.TrimSpace(value)] = true
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		dst = append(dst, value)
	}
	return dst
}
func holderIntelligenceCoreExplanationV2(core holderIntelligenceCoreResult) scanExplanationV2 {
	return buildScanExplanationV2(scanExplanationInput{Target: core.Request.Target, RiskIndex: float64(core.Final.RiskIndex), RiskLevel: core.Final.RiskLevel, Signed: core.Final.Signed, Policy: holderIntelligenceCorePolicy(core), Distribution: core.Distribution, Holder: core.Intelligence, Cluster: core.Cluster, Launch: core.LaunchForensics, Modules: radarDetailModules(core.Arms), RepeatDominant: core.RepeatDominantHolders})
}
func holderIntelligenceCoreExplanation(core holderIntelligenceCoreResult) string {
	return holderIntelligenceCoreExplanationV2(core).Text
}

type customerTokenScanResult struct {
	web3.TokenRiskResult
	HolderDistribution   map[string]any                    `json:"holder_distribution"`
	HolderIntelligence   services.HolderIntelligence       `json:"holder_intelligence"`
	HolderCluster        services.HolderClusterAnalysis    `json:"holder_cluster"`
	LaunchForensics      services.LaunchForensicsAnalysis  `json:"launch_forensics"`
	ThreatAnticipation   services.ThreatAnticipationReport `json:"threat_anticipation"`
	VerifiedEvidence     []string                          `json:"verified_evidence"`
	Explanation          string                            `json:"explanation"`
	ExplanationV2        scanExplanationV2                 `json:"explanation_v2"`
	HolderAnalysisStatus string                            `json:"holder_analysis_status"`
	FinalPolicy          string                            `json:"final_policy"`
	VerdictWithheld      bool                              `json:"verdict_withheld"`
	InvestigationReport  map[string]any                    `json:"investigation_report"`
}

func (h *Handler) scanCustomerToken(ctx context.Context, network, mint string) (customerTokenScanResult, error) {
	base, err := h.tokenService().ScanToken(ctx, network, mint)
	if err != nil {
		return customerTokenScanResult{}, err
	}
	core := h.runHolderIntelligenceCore(ctx, mint, network, "customer_token_scan")
	assembly := h.assembleUnifiedInvestigationReport(ctx, core)
	return applyHolderCoreToTokenRisk(base, core, assembly.Report), nil
}
func applyHolderCoreToTokenRisk(base web3.TokenRiskResult, core holderIntelligenceCoreResult, investigationReport map[string]any) customerTokenScanResult {
	base.Token.LargestHolderPercent = 0
	base.Token.TopTenPercent = 0
	if top1, top10, ok := holderIntelligenceCoreConcentration(core); ok {
		base.Token.LargestHolderPercent = roundPercent(top1)
		base.Token.TopTenPercent = roundPercent(top10)
	}
	rescored := web3.ScoreTokenRisk(base.Token)
	rescored.RiskLevel = tokenRiskLevel(rescored.Score)
	if strings.TrimSpace(base.Disclaimer) != "" {
		rescored.Disclaimer = base.Disclaimer
	}
	rescored.Findings = appendUniqueHolderCoreEvidence(rescored.Findings, holderIntelligenceCoreEvidence(core)...)
	policy := holderIntelligenceCorePolicy(core)
	if policy == "withhold" {
		rescored.Findings = appendUniqueHolderCoreEvidence(rescored.Findings, "Holder verdict withheld: unresolved or incomplete holder evidence is not a low-risk signal.")
	}
	return customerTokenScanResult{TokenRiskResult: rescored, HolderDistribution: core.Distribution, HolderIntelligence: core.Intelligence, HolderCluster: core.Cluster, LaunchForensics: core.LaunchForensics, ThreatAnticipation: core.ThreatAnticipation, VerifiedEvidence: holderIntelligenceCoreEvidence(core), Explanation: holderIntelligenceCoreExplanation(core), ExplanationV2: holderIntelligenceCoreExplanationV2(core), HolderAnalysisStatus: holderIntelligenceCoreStatus(core), FinalPolicy: policy, VerdictWithheld: policy == "withhold", InvestigationReport: investigationReport}
}
func holderIntelligenceCoreShieldAction(core holderIntelligenceCoreResult) string {
	if holderIntelligenceCorePolicy(core) == "withhold" || !core.Final.Signed {
		return "withhold"
	}
	return shieldAction(core.Final.RiskLevel, core.Final.RiskIndex)
}
