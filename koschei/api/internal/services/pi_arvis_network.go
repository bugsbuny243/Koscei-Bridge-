package services

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const piArvisNetworkEvidenceRuleset = "koschei-arvis-pi-evidence-v2"

// analyzePiArvisRadarsNetworkContext is the production Pi dispatcher used by
// multichain ARVIS. It keeps the existing Pi evidence semantics, but binds every
// observation to an explicit Pi mainnet or testnet transport.
func analyzePiArvisRadarsNetworkContext(ctx context.Context, req SecurityRadarRequest, target PiRadarTarget) ArvisAnalysis {
	if ctx == nil {
		ctx = context.Background()
	}
	network, ok := NormalizePiRadarNetwork(req.Network)
	if !ok {
		network = DefaultPiRadarNetwork()
	}
	req.Network = network
	if req.Mode == "" {
		req.Mode = SecurityRadarWatchMode
	}

	generatedAt := time.Now().UTC().Format(time.RFC3339)
	snapshot := collectPiHorizonSnapshotForNetwork(ctx, target, network)
	label := PiRadarNetworkLabel(network)

	pump := piNotApplicableArm("Pump.fun Sybil Radar", ModulePumpSybilRadar, req, generatedAt, "Pump.fun is a Solana-specific program surface and is not applicable to Pi assets.")
	raydium := piNotApplicableArm("Raydium Pool Guardian", ModuleRaydiumPoolGuardian, req, generatedAt, "Raydium is a Solana-specific AMM surface and is not applicable to Pi assets.")
	claimShield := piPendingArm("Walletless Claim Shield", ModuleWalletlessClaimShield, req, generatedAt, "Pi claim/sponsored-operation evidence is not implemented in the Pi adapter yet.")
	mev := piPendingArm("MEV Shield", ModuleMEVShield, req, generatedAt, "Pi DEX route and signed transaction context are required before MEV analysis can be claimed.")
	authority := buildPiAuthorityArm(req, snapshot, generatedAt)
	holders := buildPiHolderArm(req, snapshot, generatedAt)
	liquidity := buildPiLiquidityArm(req, snapshot, generatedAt)
	creator := buildPiIssuerArm(req, snapshot, generatedAt)
	funding := piPendingArm("Funding Cluster Detector", ModuleFundingClusterDetector, req, generatedAt, "Pi-specific account funding provenance has not been collected yet.")
	launch := buildPiLaunchDistributionArm(req, snapshot, generatedAt)
	repeat := piPendingArm("Repeat Actor Scan", ModuleRepeatActorScan, req, generatedAt, "Durable Pi issuer/actor memory has not been attached yet.")
	sniper := buildPiTimingArm(req, snapshot, generatedAt)
	claimSurface := buildPiClaimSurfaceArm(req, snapshot, generatedAt)
	program := piNotApplicableArm("Program Relation Scan", ModuleProgramRelationScan, req, generatedAt, "Pi assets use an issuer/trustline asset model; Solana program-owner analysis is not applicable.")

	arms := []SecurityRadarVerdict{pump, raydium, claimShield, mev, authority, holders, liquidity, creator, funding, launch, repeat, sniper, claimSurface, program}
	arms = applyRuntimeSecurityModulePolicy(req, generatedAt, arms)
	arms = rewritePiNetworkEvidenceLabels(arms, label)
	graph := buildPiIntelligenceGraph(req, snapshot, generatedAt)
	if !runtimeModuleEnabledForPiGraph() {
		graph = piPendingArm("Intelligence Graph", ModuleIntelligenceGraph, req, generatedAt, "Module disabled by KOSCHEI_SECURITY_MODULES runtime policy.")
	}
	graph = rewritePiNetworkVerdictLabel(graph, label)

	observed := piObservedEvidenceArmCount(arms)
	status := "insufficient_evidence"
	if snapshot.Available {
		status = "observed"
	}
	if len(snapshot.Errors) > 0 && snapshot.Available {
		status = "partial_observation"
	}
	summary := label + " evidence is unavailable; no risk grade was issued."
	if observed > 0 {
		summary = fmt.Sprintf("ARVIS collected %s evidence in %d of 14 arms. Pi grading remains disabled until a Pi-specific deterministic ruleset passes its regression corpus.", label, observed)
	}

	final := SecurityRadarFinalVerdict{
		Grade:          "-",
		RiskIndex:      0,
		RiskLevel:      "unknown",
		Verdict:        "Pi evidence collected without a validated Pi grading ruleset; no final risk grade is issued.",
		Recommendation: "review_pi_evidence",
		RuleVersion:    piArvisNetworkEvidenceRuleset,
		Signed:         false,
	}
	bundle := SecurityRadarBundle{
		Target: req.Target, Network: network, Provider: snapshot.Source, WatchMode: req.Mode,
		PumpSybilRadar: pump, RaydiumPoolGuardian: raydium, WalletlessClaimShield: claimShield,
		CustomerSummary: summary, CustomerRecommendation: final.Recommendation,
		Metadata: map[string]any{
			"brand":                          "KOSCHEİ WEB3",
			"sub_product":                    "ARVIS",
			"chain":                          "pi",
			"chain_adapter":                  "pi_horizon_v2",
			"provider":                       snapshot.Source,
			"network":                        network,
			"network_label":                  label,
			"ruleset":                        piArvisNetworkEvidenceRuleset,
			"architecture_arm_count":         14,
			"evidence_arm_count":             14,
			"observed_arm_count":             observed,
			"signed_grade_enabled":           false,
			"numeric_arm_scoring_disabled":   true,
			"evidence_status":                status,
			"horizon_errors":                 append([]string{}, snapshot.Errors...),
			"holder_window_complete":         snapshot.HolderWindowComplete,
			"holder_pages_fetched":           snapshot.HolderPagesFetched,
			"pi_target":                      target,
			"arvis_arms":                     arms,
			"intelligence_graph":             graph,
			"graph_is_presentation_layer":    true,
			"final_verdict_source":           "pi_ruleset_not_yet_enabled",
			"unknown_is_not_safe":            true,
			"wallet_secrets_required":        false,
			"transaction_submission_enabled": false,
		},
	}
	return ArvisAnalysis{Bundle: bundle, Arms: arms, Graph: graph, Final: final}
}

func rewritePiNetworkEvidenceLabels(arms []SecurityRadarVerdict, label string) []SecurityRadarVerdict {
	out := append([]SecurityRadarVerdict{}, arms...)
	for index := range out {
		out[index] = rewritePiNetworkVerdictLabel(out[index], label)
	}
	return out
}

func rewritePiNetworkVerdictLabel(verdict SecurityRadarVerdict, label string) SecurityRadarVerdict {
	if label == "Pi Testnet" {
		return verdict
	}
	replace := func(value string) string {
		value = strings.ReplaceAll(value, "Pi Testnet", label)
		value = strings.ReplaceAll(value, "Test-Pi/target-asset", "Pi/target-asset")
		return value
	}
	verdict.Verdict = replace(verdict.Verdict)
	verdict.Recommendation = replace(verdict.Recommendation)
	for index := range verdict.Evidence {
		verdict.Evidence[index] = replace(verdict.Evidence[index])
	}
	return verdict
}
