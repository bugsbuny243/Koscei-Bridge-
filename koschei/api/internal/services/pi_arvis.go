package services

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const piArvisEvidenceRuleset = "koschei-arvis-pi-evidence-v1"

func analyzePiArvisRadarsContext(ctx context.Context, req SecurityRadarRequest, target PiRadarTarget) ArvisAnalysis {
	if ctx == nil {
		ctx = context.Background()
	}
	req.Network = piTestnetNetwork
	if req.Mode == "" {
		req.Mode = SecurityRadarWatchMode
	}
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	snapshot := collectPiHorizonSnapshot(ctx, target)

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
	graph := buildPiIntelligenceGraph(req, snapshot, generatedAt)
	if !runtimeModuleEnabledForPiGraph() {
		graph = piPendingArm("Intelligence Graph", ModuleIntelligenceGraph, req, generatedAt, "Module disabled by KOSCHEI_SECURITY_MODULES runtime policy.")
	}

	observed := piObservedEvidenceArmCount(arms)
	status := "insufficient_evidence"
	if snapshot.Available {
		status = "observed"
	}
	if len(snapshot.Errors) > 0 && snapshot.Available {
		status = "partial_observation"
	}
	summary := "Pi evidence is unavailable; no risk grade was issued."
	if observed > 0 {
		summary = fmt.Sprintf("ARVIS collected Pi Testnet evidence in %d of 14 arms. Pi grading remains disabled until a Pi-specific deterministic ruleset passes its regression corpus.", observed)
	}

	final := SecurityRadarFinalVerdict{
		Grade:          "-",
		RiskIndex:      0,
		RiskLevel:      "unknown",
		Verdict:        "Pi evidence collected without a validated Pi grading ruleset; no final risk grade is issued.",
		Recommendation: "review_pi_evidence",
		RuleVersion:    piArvisEvidenceRuleset,
		Signed:         false,
	}
	bundle := SecurityRadarBundle{
		Target: req.Target, Network: req.Network, Provider: piRadarEvidenceSourceHorizon, WatchMode: req.Mode,
		PumpSybilRadar: pump, RaydiumPoolGuardian: raydium, WalletlessClaimShield: claimShield,
		CustomerSummary: summary, CustomerRecommendation: final.Recommendation,
		Metadata: map[string]any{
			"brand":                         "KOSCHEİ WEB3",
			"sub_product":                   "ARVIS",
			"chain_adapter":                 "pi_horizon_v1",
			"provider":                      piRadarEvidenceSourceHorizon,
			"network":                       piTestnetNetwork,
			"ruleset":                       piArvisEvidenceRuleset,
			"architecture_arm_count":        14,
			"evidence_arm_count":            14,
			"observed_arm_count":            observed,
			"signed_grade_enabled":          false,
			"numeric_arm_scoring_disabled":  true,
			"evidence_status":               status,
			"horizon_errors":                append([]string{}, snapshot.Errors...),
			"holder_window_complete":        snapshot.HolderWindowComplete,
			"holder_pages_fetched":          snapshot.HolderPagesFetched,
			"pi_target":                     target,
			"arvis_arms":                    arms,
			"intelligence_graph":            graph,
			"graph_is_presentation_layer":   true,
			"final_verdict_source":          "pi_ruleset_not_yet_enabled",
			"unknown_is_not_safe":           true,
			"wallet_secrets_required":       false,
			"transaction_submission_enabled": false,
		},
	}
	return ArvisAnalysis{Bundle: bundle, Arms: arms, Graph: graph, Final: final}
}

func runtimeModuleEnabledForPiGraph() bool {
	// Kept behind the same runtime module policy as the Solana presentation graph.
	return runtimeModuleEnabled(ModuleIntelligenceGraph)
}

func runtimeModuleEnabled(module string) bool {
	// A small wrapper keeps Pi adapter code isolated from runtimecfg imports.
	return arvisRuntimeModuleEnabled(module)
}

func buildPiAuthorityArm(req SecurityRadarRequest, snapshot piHorizonSnapshot, generatedAt string) SecurityRadarVerdict {
	if snapshot.Target.Kind != piRadarTargetKindAsset || snapshot.IssuerAccount == nil {
		return piPendingArm("Token Authority Scanner", ModuleTokenAuthorityScanner, req, generatedAt, "Issuer account state is required for Pi authority analysis.")
	}
	account := snapshot.IssuerAccount
	totalWeight := 0
	activeSigners := 0
	for _, signer := range account.Signers {
		if signer.Weight <= 0 {
			continue
		}
		totalWeight += signer.Weight
		activeSigners++
	}
	mediumSatisfiable := account.Thresholds.MedThreshold > 0 && totalWeight >= account.Thresholds.MedThreshold
	signals := piArmSignals(ModuleTokenAuthorityScanner, snapshot)
	signals["issuer"] = snapshot.Target.Issuer
	signals["active_signer_count"] = activeSigners
	signals["active_signer_weight_sum"] = totalWeight
	signals["low_threshold"] = account.Thresholds.LowThreshold
	signals["medium_threshold"] = account.Thresholds.MedThreshold
	signals["high_threshold"] = account.Thresholds.HighThreshold
	signals["medium_threshold_satisfiable"] = mediumSatisfiable
	signals["scope_note"] = "This reports current signer/threshold capability. It does not infer real-world controller identity."
	evidence := []string{
		fmt.Sprintf("Pi Horizon issuer account observed with %d active signer(s) and active signer weight sum %d.", activeSigners, totalWeight),
		fmt.Sprintf("Issuer thresholds observed: low=%d medium=%d high=%d.", account.Thresholds.LowThreshold, account.Thresholds.MedThreshold, account.Thresholds.HighThreshold),
		fmt.Sprintf("Current signer weights can satisfy the observed medium threshold: %t.", mediumSatisfiable),
	}
	return piObservedArm("Token Authority Scanner", ModuleTokenAuthorityScanner, req, generatedAt, signals, evidence)
}

func buildPiHolderArm(req SecurityRadarRequest, snapshot piHorizonSnapshot, generatedAt string) SecurityRadarVerdict {
	if snapshot.Target.Kind != piRadarTargetKindAsset || len(snapshot.Holders) == 0 {
		return piPendingArm("Holder Concentration", ModuleHolderConcentration, req, generatedAt, "Pi trustline holder balances were not observed.")
	}
	total := 0.0
	balances := make([]float64, 0, len(snapshot.Holders))
	for _, holder := range snapshot.Holders {
		if holder.Balance <= 0 {
			continue
		}
		total += holder.Balance
		balances = append(balances, holder.Balance)
	}
	if total <= 0 || len(balances) == 0 {
		return piPendingArm("Holder Concentration", ModuleHolderConcentration, req, generatedAt, "Observed trustlines did not contain a positive target-asset balance.")
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(balances)))
	top1 := balances[0] / total * 100
	top10Amount := 0.0
	for index := 0; index < len(balances) && index < 10; index++ {
		top10Amount += balances[index]
	}
	top10 := top10Amount / total * 100
	signals := piArmSignals(ModuleHolderConcentration, snapshot)
	signals["trustline_holder_count_observed"] = len(snapshot.Holders)
	signals["observed_account_balance_total"] = total
	signals["observed_largest_account_share_pct"] = math.Round(top1*10000) / 10000
	signals["observed_top_10_account_share_pct"] = math.Round(top10*10000) / 10000
	signals["holder_window_complete"] = snapshot.HolderWindowComplete
	signals["holder_pages_fetched"] = snapshot.HolderPagesFetched
	signals["scope_note"] = "Shares are among observed account trustline balances; liquidity-pool and claimable-balance inventory are not silently reclassified as wallet control."
	evidence := []string{
		fmt.Sprintf("Observed %d Pi account trustline balance(s) for the exact asset.", len(snapshot.Holders)),
		fmt.Sprintf("Largest observed account share is %.4f%% and observed top-10 share is %.4f%% of account-held balances in this evidence set.", top1, top10),
	}
	if !snapshot.HolderWindowComplete {
		evidence = append(evidence, "Holder pagination hit the configured evidence bound; concentration is a bounded observation and is not a complete holder-distribution claim.")
	}
	return piObservedArm("Holder Concentration", ModuleHolderConcentration, req, generatedAt, signals, evidence)
}

func buildPiLiquidityArm(req SecurityRadarRequest, snapshot piHorizonSnapshot, generatedAt string) SecurityRadarVerdict {
	if snapshot.Target.Kind != piRadarTargetKindAsset || !snapshot.LiquidityQuerySuccessful {
		return piPendingArm("Liquidity Movement", ModuleLiquidityMovement, req, generatedAt, "Pi Testnet liquidity-pool state was not available from the current Horizon evidence window.")
	}
	signals := piArmSignals(ModuleLiquidityMovement, snapshot)
	signals["liquidity_pool_count_observed"] = len(snapshot.LiquidityPools)
	signals["movement_verified"] = false
	signals["scope_note"] = "Current pool state is observed; liquidity add/remove movement requires transaction-backed reserve deltas and remains unknown."
	evidence := []string{fmt.Sprintf("Pi Horizon returned %d current liquidity-pool record(s) for the Test-Pi/target-asset reserve filter.", len(snapshot.LiquidityPools)), "No historical reserve delta is inferred from a current-state pool response."}
	return piObservedArm("Liquidity Movement", ModuleLiquidityMovement, req, generatedAt, signals, evidence)
}

func buildPiIssuerArm(req SecurityRadarRequest, snapshot piHorizonSnapshot, generatedAt string) SecurityRadarVerdict {
	if snapshot.Target.Kind != piRadarTargetKindAsset || snapshot.IssuerAccount == nil {
		return piPendingArm("Creator Link Analysis", ModuleCreatorLinkAnalysis, req, generatedAt, "Pi issuer account evidence is required.")
	}
	signals := piArmSignals(ModuleCreatorLinkAnalysis, snapshot)
	signals["protocol_issuer"] = snapshot.Target.Issuer
	signals["home_domain"] = snapshot.IssuerAccount.HomeDomain
	signals["identity_claim"] = false
	evidence := []string{fmt.Sprintf("The exact asset identifier names %s as its on-chain issuer account.", snapshot.Target.Issuer), "Issuer provenance is a protocol relation only; it is not proof of a real-world creator identity."}
	return piObservedArm("Creator Link Analysis", ModuleCreatorLinkAnalysis, req, generatedAt, signals, evidence)
}

func buildPiLaunchDistributionArm(req SecurityRadarRequest, snapshot piHorizonSnapshot, generatedAt string) SecurityRadarVerdict {
	if snapshot.Target.Kind != piRadarTargetKindAsset || len(snapshot.IssuerPayments) == 0 {
		return piPendingArm("Launch Distribution", ModuleLaunchDistribution, req, generatedAt, "No exact-asset issuer payment was observed in the bounded Pi Horizon payment window.")
	}
	payments := snapshot.IssuerPayments
	first := payments[0]
	total := 0.0
	for _, payment := range payments {
		amount, err := strconv.ParseFloat(payment.Amount, 64)
		if err == nil && amount > 0 {
			total += amount
		}
	}
	signals := piArmSignals(ModuleLaunchDistribution, snapshot)
	signals["issuer_payment_count_observed"] = len(payments)
	signals["issuer_payment_amount_observed"] = total
	signals["earliest_observed_transaction"] = first.TransactionHash
	signals["earliest_observed_destination"] = first.To
	signals["earliest_observed_at"] = first.CreatedAt
	signals["payment_window_limit"] = piHorizonPaymentLimit
	signals["history_complete"] = false
	evidence := []string{
		fmt.Sprintf("Observed %d issuer-originated payment operation(s) for the exact Pi asset in the bounded window.", len(payments)),
		fmt.Sprintf("Earliest observed exact-asset payment in the window: transaction=%s destination=%s amount=%s timestamp=%s.", first.TransactionHash, first.To, first.Amount, first.CreatedAt),
		"The payment window is bounded and is not represented as complete launch history.",
	}
	return piObservedArm("Launch Distribution", ModuleLaunchDistribution, req, generatedAt, signals, evidence)
}

func buildPiTimingArm(req SecurityRadarRequest, snapshot piHorizonSnapshot, generatedAt string) SecurityRadarVerdict {
	if len(snapshot.IssuerPayments) == 0 {
		return piPendingArm("Sniper Timing Detector", ModuleSniperTimingDetector, req, generatedAt, "Pi launch/acquisition timing requires exact-asset payment evidence.")
	}
	first := snapshot.IssuerPayments[0]
	signals := piArmSignals(ModuleSniperTimingDetector, snapshot)
	signals["earliest_observed_issuance_at"] = first.CreatedAt
	signals["timing_coordination_claim"] = false
	evidence := []string{fmt.Sprintf("Earliest exact-asset issuer payment observed in the bounded Horizon window at %s.", first.CreatedAt), "A bounded issuer payment timestamp alone is not evidence of coordinated sniping."}
	return piObservedArm("Sniper Timing Detector", ModuleSniperTimingDetector, req, generatedAt, signals, evidence)
}

func buildPiClaimSurfaceArm(req SecurityRadarRequest, snapshot piHorizonSnapshot, generatedAt string) SecurityRadarVerdict {
	account := snapshot.IssuerAccount
	if snapshot.Target.Kind == piRadarTargetKindAccount {
		account = snapshot.WalletAccount
	}
	if account == nil {
		return piPendingArm("Claim Surface Risk", ModuleClaimSurfaceRisk, req, generatedAt, "Pi account home-domain evidence is unavailable.")
	}
	signals := piArmSignals(ModuleClaimSurfaceRisk, snapshot)
	signals["home_domain"] = account.HomeDomain
	signals["domain_verified"] = false
	if strings.TrimSpace(account.HomeDomain) == "" {
		return piObservedArm("Claim Surface Risk", ModuleClaimSurfaceRisk, req, generatedAt, signals, []string{"No home_domain is currently present on the observed Pi account. This is metadata state, not a safety verdict."})
	}
	return piObservedArm("Claim Surface Risk", ModuleClaimSurfaceRisk, req, generatedAt, signals, []string{fmt.Sprintf("Pi Horizon reports home_domain=%s on the observed account.", account.HomeDomain), "The domain and /.well-known/pi.toml have not yet been independently fetched or verified by ARVIS."})
}

func buildPiIntelligenceGraph(req SecurityRadarRequest, snapshot piHorizonSnapshot, generatedAt string) SecurityRadarVerdict {
	nodes := []map[string]any{{"id": req.Target, "kind": snapshot.Target.Kind, "chain": "pi"}}
	edges := []map[string]any{}
	if snapshot.Target.Kind == piRadarTargetKindAsset {
		nodes = append(nodes, map[string]any{"id": snapshot.Target.Issuer, "kind": "issuer_account", "chain": "pi"})
		edges = append(edges, map[string]any{"source": req.Target, "destination": snapshot.Target.Issuer, "relation": "issued_by", "evidence_status": "observed"})
		for index, payment := range snapshot.IssuerPayments {
			if index >= 20 || strings.TrimSpace(payment.To) == "" {
				break
			}
			nodes = append(nodes, map[string]any{"id": payment.To, "kind": "payment_recipient", "chain": "pi"})
			edges = append(edges, map[string]any{"source": snapshot.Target.Issuer, "destination": payment.To, "relation": "asset_payment", "transaction_hash": payment.TransactionHash, "amount": payment.Amount, "timestamp": payment.CreatedAt, "evidence_status": "observed"})
		}
	}
	if len(edges) == 0 && snapshot.Target.Kind != piRadarTargetKindAccount {
		return piPendingArm("Intelligence Graph", ModuleIntelligenceGraph, req, generatedAt, "Pi issuer or payment relations were not available for graph materialization.")
	}
	signals := piArmSignals(ModuleIntelligenceGraph, snapshot)
	signals["presentation_layer"] = true
	signals["nodes"] = nodes
	signals["edges"] = edges
	return piObservedArm("Intelligence Graph", ModuleIntelligenceGraph, req, generatedAt, signals, []string{"Graph relations are materialized only from Pi Horizon evidence already collected by the adapter."})
}

func piArmSignals(moduleID string, snapshot piHorizonSnapshot) map[string]any {
	return map[string]any{
		"module_id":                  moduleID,
		"chain":                      "pi",
		"network":                    piTestnetNetwork,
		"provider":                   piRadarEvidenceSourceHorizon,
		"ruleset":                    piArvisEvidenceRuleset,
		"real_onchain_evidence":      snapshot.Available,
		"numeric_score_disabled":     true,
		"grade_effect":               "none_at_arm_layer",
		"signed_grade_enabled":       false,
		"unverified_claims_allowed":  false,
		"unknown_is_not_safe":        true,
		"wallet_secrets_required":    false,
	}
}

func piObservedArm(module, moduleID string, req SecurityRadarRequest, generatedAt string, signals map[string]any, evidence []string) SecurityRadarVerdict {
	if signals == nil {
		signals = map[string]any{}
	}
	signals["arm_evidence_available"] = true
	signals["evidence_status"] = "observed"
	signals["grade_effect"] = "none_at_arm_layer"
	return SecurityRadarVerdict{Module: module, ModuleID: moduleID, Target: req.Target, Network: req.Network, Grade: "-", RiskIndex: 0, RiskLevel: "evidence_only", Verdict: "Pi Testnet evidence observed; no Pi risk grade is enabled.", Recommendation: "review_pi_evidence", Signals: signals, Evidence: evidence, GeneratedAt: generatedAt, RuleVersion: piArvisEvidenceRuleset, Signed: false}
}

func piPendingArm(module, moduleID string, req SecurityRadarRequest, generatedAt, reason string) SecurityRadarVerdict {
	return SecurityRadarVerdict{Module: module, ModuleID: moduleID, Target: req.Target, Network: req.Network, Grade: "-", RiskIndex: 0, RiskLevel: "unknown", Verdict: SecurityRadarInsufficientEvidenceMessage, Recommendation: "insufficient_evidence", Signals: map[string]any{"module_id": moduleID, "chain": "pi", "network": piTestnetNetwork, "provider": piRadarEvidenceSourceHorizon, "ruleset": piArvisEvidenceRuleset, "arm_evidence_available": false, "evidence_status": "insufficient_evidence", "numeric_score_disabled": true, "grade_effect": "none_at_arm_layer", "signed_grade_enabled": false, "unknown_is_not_safe": true}, Evidence: []string{reason}, GeneratedAt: generatedAt, RuleVersion: piArvisEvidenceRuleset, Signed: false}
}

func piNotApplicableArm(module, moduleID string, req SecurityRadarRequest, generatedAt, reason string) SecurityRadarVerdict {
	return SecurityRadarVerdict{Module: module, ModuleID: moduleID, Target: req.Target, Network: req.Network, Grade: "-", RiskIndex: 0, RiskLevel: "not_applicable", Verdict: "Not applicable to the Pi chain adapter.", Recommendation: "not_applicable", Signals: map[string]any{"module_id": moduleID, "chain": "pi", "network": piTestnetNetwork, "provider": piRadarEvidenceSourceHorizon, "ruleset": piArvisEvidenceRuleset, "arm_evidence_available": false, "evidence_status": "not_applicable", "numeric_score_disabled": true, "grade_effect": "none_at_arm_layer", "signed_grade_enabled": false}, Evidence: []string{reason}, GeneratedAt: generatedAt, RuleVersion: piArvisEvidenceRuleset, Signed: false}
}

func piObservedEvidenceArmCount(arms []SecurityRadarVerdict) int {
	count := 0
	for _, arm := range arms {
		if arm.Signals != nil && fmt.Sprint(arm.Signals["evidence_status"]) == "observed" {
			count++
		}
	}
	return count
}
