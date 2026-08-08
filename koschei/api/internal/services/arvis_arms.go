package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"koschei/api/internal/runtimecfg"
)

const (
	ModuleIntelligenceGraph      = "intelligence_graph"
	ModuleMEVShield              = "mev_shield"
	ModuleTokenAuthorityScanner  = "token_authority_scanner"
	ModuleHolderConcentration    = "holder_concentration"
	ModuleLiquidityMovement      = "liquidity_movement"
	ModuleCreatorLinkAnalysis    = "creator_link_analysis"
	ModuleFundingClusterDetector = "funding_cluster_detector"
	ModuleLaunchDistribution     = "launch_distribution"
	ModuleRepeatActorScan        = "repeat_actor_scan"
	ModuleSniperTimingDetector   = "sniper_timing_detector"
	ModuleClaimSurfaceRisk       = "claim_surface_risk"
	ModuleProgramRelationScan    = "program_relation_scan"
	// Compatibility identifier only. Final verdicts are produced by
	// EvaluateUnifiedRadarVerdict, never by an ARVIS arm.
	ModuleFinalVerdictEngine = "final_verdict_engine"
)

type ArvisAnalysis struct {
	Bundle SecurityRadarBundle       `json:"bundle"`
	Arms   []SecurityRadarVerdict    `json:"arms"`
	Graph  SecurityRadarVerdict      `json:"intelligence_graph"`
	Final  SecurityRadarFinalVerdict `json:"final_verdict"`
}

func AnalyzeArvisRadars(req SecurityRadarRequest) ArvisAnalysis {
	return AnalyzeArvisRadarsContext(context.Background(), req)
}

func AnalyzeArvisRadarsContext(ctx context.Context, req SecurityRadarRequest) ArvisAnalysis {
	if ctx == nil {
		ctx = context.Background()
	}
	req.Target = strings.TrimSpace(req.Target)
	req.Network = strings.TrimSpace(req.Network)
	req.Mode = strings.TrimSpace(req.Mode)
	if req.Network == "" {
		req.Network = "solana-mainnet"
	}
	if req.Mode == "" {
		req.Mode = SecurityRadarWatchMode
	}

	generatedAt := time.Now().UTC().Format(time.RFC3339)
	profile := collectRadarEvidenceContext(ctx, req)
	sourceModule := arvisSourceModule(req.Mode)

	pump := buildPumpProgramApplicabilityArm(req, profile, generatedAt)
	raydium := buildRaydiumProgramApplicabilityArm(req, profile, generatedAt)

	claimShield := unavailableArm("Walletless Claim Shield", ModuleWalletlessClaimShield, req, generatedAt, "A parsed claim instruction is required; token-holder evidence is not a claim-surface substitute.")
	mev := unavailableArm("MEV Shield", ModuleMEVShield, req, generatedAt, "A signed transaction, route and pool context are required for MEV analysis.")
	authority := buildAuthorityArm(req, profile, generatedAt)
	holders := buildHolderArm(req, profile, generatedAt)
	liquidity := unavailableArm("Liquidity Movement", ModuleLiquidityMovement, req, generatedAt, "Pool reserve or market-liquidity evidence has not been attached yet.")
	creator := unavailableArm("Creator Link Analysis", ModuleCreatorLinkAnalysis, req, generatedAt, "Creator/deployer evidence has not been attached yet.")
	funding := buildFundingClusterArm(req, profile, generatedAt)
	launchDistribution := unavailableArm("Launch Distribution", ModuleLaunchDistribution, req, generatedAt, "Mint-specific ATA initial-recipient evidence has not been attached yet.")
	repeatActors := unavailableArm("Repeat Actor Scan", ModuleRepeatActorScan, req, generatedAt, "Persistent creator/holder actor-index evidence has not been attached yet.")
	sniper := buildSniperTimingArm(req, profile, generatedAt)
	claimSurface := unavailableArm("Claim Surface Risk", ModuleClaimSurfaceRisk, req, generatedAt, "URL/domain evidence is required; claim-instruction evidence belongs to Walletless Claim Shield.")
	program := buildProgramRelationArm(req, profile, generatedAt)

	// Exactly fourteen evidence arms. Intelligence Graph is a presentation layer
	// and the final verdict is owned by the unified deterministic rules engine.
	arms := []SecurityRadarVerdict{
		pump, raydium, claimShield, mev, authority, holders, liquidity,
		creator, funding, launchDistribution, repeatActors, sniper,
		claimSurface, program,
	}
	arms = applyRuntimeSecurityModulePolicy(req, generatedAt, arms)
	graph := buildIntelligenceGraphArm(req, profile, generatedAt)
	if !runtimecfg.ModuleEnabled(ModuleIntelligenceGraph) {
		graph = unavailableArm("Intelligence Graph", ModuleIntelligenceGraph, req, generatedAt, "Module disabled by KOSCHEI_SECURITY_MODULES runtime policy.")
	}
	final := arvisCompatibilityFinal()
	verified := verifiedArvisEvidenceCount(arms)

	summary := SecurityRadarInsufficientEvidenceMessage
	if verified > 0 {
		summary = fmt.Sprintf("ARVIS collected evidence from %d of 14 single-responsibility arms. Letter grade is produced only by EvaluateUnifiedRadarVerdict.", verified)
	}
	bundle := SecurityRadarBundle{
		Target: req.Target, Network: req.Network, Provider: SecurityRadarProvider, WatchMode: req.Mode,
		PumpSybilRadar: pump, RaydiumPoolGuardian: raydium, WalletlessClaimShield: claimShield,
		CustomerSummary: summary, CustomerRecommendation: "evaluate_unified_rules",
		Metadata: map[string]any{
			"brand": "KOSCHEİ WEB3", "sub_product": "ARVIS", "mode": req.Mode,
			"provider": SecurityRadarProvider, "watch_mode": req.Mode, "rule_version": SecurityRadarRuleVersion,
			"architecture_arm_count": 14, "evidence_arm_count": 14, "verified_arm_count": verified,
			"runtime_arm_count": verified, "arvis_arms": arms, "source_module": sourceModule,
			"intelligence_graph":             graph,
			"graph_is_presentation_layer":    true,
			"final_verdict_source":           "EvaluateUnifiedRadarVerdict",
			"numeric_arm_scoring_disabled":   true,
			"investigation_capabilities":     ArvisInvestigationCapabilities(),
			"investigation_capability_scope": ArvisCapabilityRulesetScope,
			"data_quality":                   profile.DataQuality, "evidence_status": profile.EvidenceStatus,
			"holder_cluster_analysis": profile.HolderCluster,
			"funding_recurrence":      profile.FundingRecurrence,
		},
	}
	return ArvisAnalysis{Bundle: bundle, Arms: arms, Graph: graph, Final: final}
}

func applyRuntimeSecurityModulePolicy(req SecurityRadarRequest, generatedAt string, arms []SecurityRadarVerdict) []SecurityRadarVerdict {
	out := make([]SecurityRadarVerdict, 0, len(arms))
	for _, arm := range arms {
		if runtimecfg.ModuleEnabled(arm.ModuleID) {
			out = append(out, arm)
			continue
		}
		out = append(out, unavailableArm(arm.Module, arm.ModuleID, req, generatedAt, "Module disabled by KOSCHEI_SECURITY_MODULES runtime policy."))
	}
	return out
}

func ArvisArmsFromBundle(bundle SecurityRadarBundle) []SecurityRadarVerdict {
	if bundle.Metadata == nil {
		return nil
	}
	switch raw := bundle.Metadata["arvis_arms"].(type) {
	case []SecurityRadarVerdict:
		return raw
	case []any:
		out := make([]SecurityRadarVerdict, 0, len(raw))
		for _, item := range raw {
			if verdict, ok := item.(SecurityRadarVerdict); ok {
				out = append(out, verdict)
			}
		}
		return out
	default:
		return nil
	}
}

func ArvisFinalFromBundle(_ SecurityRadarBundle) SecurityRadarFinalVerdict {
	return arvisCompatibilityFinal()
}

func arvisCompatibilityFinal() SecurityRadarFinalVerdict {
	return SecurityRadarFinalVerdict{
		Grade: "-", RiskIndex: 0, RiskLevel: "unknown",
		Verdict:        "No ARVIS arm may issue a final grade. EvaluateUnifiedRadarVerdict is authoritative.",
		Recommendation: "evaluate_unified_rules", RuleVersion: UnifiedRadarRulesetVersion,
		Signed: false,
	}
}

func ArvisHolderRolesFromBundle(bundle SecurityRadarBundle) HolderRoleAnalysis {
	for _, arm := range ArvisArmsFromBundle(bundle) {
		if arm.ModuleID != ModuleHolderConcentration || arm.Signals == nil {
			continue
		}
		if value, ok := arm.Signals["holder_role_analysis"].(HolderRoleAnalysis); ok {
			return value
		}
	}
	return HolderRoleAnalysis{}
}

func ArvisHolderClusterFromBundle(bundle SecurityRadarBundle) HolderClusterAnalysis {
	if bundle.Metadata == nil {
		return HolderClusterAnalysis{}
	}
	if value, ok := bundle.Metadata["holder_cluster_analysis"].(HolderClusterAnalysis); ok {
		return value
	}
	return HolderClusterAnalysis{}
}

func arvisSourceModule(mode string) string {
	mode = strings.TrimSpace(mode)
	const prefix = "live_stream:"
	if !strings.HasPrefix(mode, prefix) {
		return ""
	}
	moduleID := strings.TrimSpace(strings.TrimPrefix(mode, prefix))
	switch moduleID {
	case ModulePumpSybilRadar, ModuleRaydiumPoolGuardian:
		return moduleID
	default:
		return ""
	}
}

func buildPumpProgramApplicabilityArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	if !p.LiveRPC || p.RecentSignatureCount <= 0 {
		return evidencePendingArm("Pump.fun Sybil Radar", ModulePumpSybilRadar, req, generatedAt, "Pump-program relation requires live RPC signature observations for this token.", "pump_signature_evidence_unavailable")
	}
	if !pumpProgramRelationObserved(req, p) {
		return notApplicableArm("Pump.fun Sybil Radar", ModulePumpSybilRadar, req, generatedAt, "No Pump program relation was observed for this token from account/program evidence.", "no_pump_program_relation")
	}
	return buildPumpProgramArm(req, p, generatedAt)
}

func buildRaydiumProgramApplicabilityArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	if !p.LiveRPC || !p.AccountExists {
		return evidencePendingArm("Raydium Pool Guardian", ModuleRaydiumPoolGuardian, req, generatedAt, "Raydium pool applicability requires live RPC account evidence for this token.", "raydium_account_evidence_unavailable")
	}
	if !raydiumProgramRelationObserved(p) {
		return notApplicableArm("Raydium Pool Guardian", ModuleRaydiumPoolGuardian, req, generatedAt, "No AMM pool or Raydium program relation was observed for this token in the current evidence context.", "no_amm_pool")
	}
	return buildRaydiumProgramArm(req, p, generatedAt)
}

func pumpProgramRelationObserved(req SecurityRadarRequest, p radarEvidenceProfile) bool {
	owner := strings.TrimSpace(p.AccountOwner)
	if owner == defaultPumpProgramID || owner == defaultPumpSwapProgramID || owner == pumpBondingCurveProgramID || owner == pumpLiquidityProgramID {
		return true
	}
	// Pump.fun mint addresses are conventionally emitted with the `pump` suffix;
	// this is treated only as an observed program-relation hint and never as a
	// grade-bearing claim. Parsed transaction/program arms can later replace it
	// with signature-backed VERIFIED evidence.
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(req.Target)), "pump")
}

func raydiumProgramRelationObserved(p radarEvidenceProfile) bool {
	return isKnownRaydiumProgram(p.AccountOwner)
}

func buildPumpProgramArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	s := armSignals(req, p, ModulePumpSybilRadar)
	s["source_verified_program_event"] = arvisSourceModule(req.Mode) == ModulePumpSybilRadar
	s["program_relation_observed"] = true
	s["recent_signature_count"] = p.RecentSignatureCount
	s["signature_window_seconds"] = p.SignatureWindowSeconds
	s["failed_signature_count"] = p.FailedSignatureCount
	s["scope_note"] = "Pump-specific program/timing evidence only; holder concentration belongs exclusively to Holder Concentration."
	e := []string{
		"Pump program relation was observed from the token evidence context.",
		fmt.Sprintf("Pump target signature window contains %d observations across %d seconds.", p.RecentSignatureCount, p.SignatureWindowSeconds),
	}
	return evidenceArm("Pump.fun Sybil Radar", ModulePumpSybilRadar, req, 0, s, e, generatedAt)
}

func buildRaydiumProgramArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	s := armSignals(req, p, ModuleRaydiumPoolGuardian)
	s["source_verified_program_event"] = arvisSourceModule(req.Mode) == ModuleRaydiumPoolGuardian
	s["program_relation_observed"] = true
	s["account_owner"] = p.AccountOwner
	s["account_executable"] = p.AccountExecutable
	s["scope_note"] = "Raydium program/pool evidence only; authorities and holder concentration belong to their own arms."
	e := []string{
		"Raydium program relation was observed from the token evidence context.",
		fmt.Sprintf("Observed account owner program: %s.", firstRadarValue(p.AccountOwner, "unknown")),
	}
	return evidenceArm("Raydium Pool Guardian", ModuleRaydiumPoolGuardian, req, 0, s, e, generatedAt)
}

// Intelligence Graph is not an evidence arm. It consumes relations already
// collected by other surfaces and never computes holder or risk thresholds.
func buildIntelligenceGraphArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	if !p.LiveRPC || !p.AccountExists || (p.AccountOwner == "" && p.LatestSignature == "") {
		return unavailableArm("Intelligence Graph", ModuleIntelligenceGraph, req, generatedAt, "Account/program or transaction relation evidence is required.")
	}
	s := map[string]any{
		"module_id":             ModuleIntelligenceGraph,
		"presentation_layer":    true,
		"real_onchain_evidence": true,
		"evidence_status":       "observed",
		"nodes":                 []map[string]any{{"id": req.Target, "kind": "target"}, {"id": p.AccountOwner, "kind": "program"}},
		"edges":                 []map[string]any{{"source": req.Target, "destination": p.AccountOwner, "relation": "owned_by_program", "evidence_status": "observed"}},
		"latest_signature":      p.LatestSignature,
		"latest_slot":           p.LatestSlot,
	}
	e := []string{
		fmt.Sprintf("Account owner relation observed: %s.", firstRadarValue(p.AccountOwner, "unknown")),
		fmt.Sprintf("Latest observed signature: %s at slot %d.", firstRadarValue(p.LatestSignature, "none"), p.LatestSlot),
	}
	return evidenceArm("Intelligence Graph", ModuleIntelligenceGraph, req, 0, s, e, generatedAt)
}

func buildAuthorityArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	if !p.LiveRPC || !p.IsTokenMint || !p.AccountExists {
		return unavailableArm("Token Authority Scanner", ModuleTokenAuthorityScanner, req, generatedAt, "A parsed token mint account is required.")
	}
	s := armSignals(req, p, ModuleTokenAuthorityScanner)
	s["mint_authority_present"] = p.MintAuthorityPresent
	s["freeze_authority_present"] = p.FreezeAuthorityPresent
	s["account_owner"] = p.AccountOwner
	e := []string{
		fmt.Sprintf("Mint authority present: %t.", p.MintAuthorityPresent),
		fmt.Sprintf("Freeze authority present: %t.", p.FreezeAuthorityPresent),
		fmt.Sprintf("Mint account owner: %s.", firstRadarValue(p.AccountOwner, "unknown")),
	}
	return evidenceArm("Token Authority Scanner", ModuleTokenAuthorityScanner, req, 0, s, e, generatedAt)
}

func buildHolderArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	if !p.LiveRPC || !p.IsTokenMint || p.LargestAccounts == 0 {
		return unavailableArm("Holder Concentration", ModuleHolderConcentration, req, generatedAt, "Token largest-account evidence is required.")
	}
	if p.HolderRoles.BlockingEvidenceGap {
		v := unavailableArm("Holder Concentration", ModuleHolderConcentration, req, generatedAt, "Dominant token-account role is unresolved; raw concentration cannot be represented as wallet control.")
		v.Signals["holder_role_analysis"] = p.HolderRoles
		v.Signals["raw_largest_holder_percentage"] = p.RawLargestHolderPct
		v.Signals["raw_top_10_holder_percentage"] = p.RawTop10HolderPct
		return v
	}
	// This is the sole ARVIS arm allowed to interpret holder concentration.
	// The returned legacy threshold diagnostic is never a final score or grade.
	legacyThresholdDiagnostic := concentrationRisk(p.LargestHolderPct, p.Top10HolderPct)
	s := armSignals(req, p, ModuleHolderConcentration)
	s["largest_holder_percentage"] = p.LargestHolderPct
	s["top_10_holder_percentage"] = p.Top10HolderPct
	s["raw_largest_holder_percentage"] = p.RawLargestHolderPct
	s["raw_top_10_holder_percentage"] = p.RawTop10HolderPct
	s["holder_role_adjusted"] = p.HolderRoles.RoleAdjusted
	s["holder_role_analysis"] = p.HolderRoles
	s["largest_accounts"] = p.LargestAccounts
	s["token_supply"] = p.TokenSupply
	s["legacy_threshold_diagnostic_deprecated"] = legacyThresholdDiagnostic
	s["grade_effect"] = "none_at_arm_layer"
	basis := "raw total supply"
	if p.HolderRoles.RoleAdjusted {
		basis = "role-adjusted circulating holder supply"
	}
	e := []string{
		fmt.Sprintf("Holder concentration basis: %s.", basis),
		fmt.Sprintf("Risk-bearing largest holder controls %d%%; Top 10 control %d%%.", p.LargestHolderPct, p.Top10HolderPct),
		fmt.Sprintf("Raw token-account concentration: Top 1=%d%% Top 10=%d%%.", p.RawLargestHolderPct, p.RawTop10HolderPct),
		fmt.Sprintf("Protocol-controlled inventory=%.4f%%; burn sinks=%.4f%%; unresolved=%.4f%%.", p.HolderRoles.ProtocolControlledPercentage, p.HolderRoles.BurnPercentage, p.HolderRoles.UnresolvedPercentage),
	}
	return evidenceArm("Holder Concentration", ModuleHolderConcentration, req, 0, s, e, generatedAt)
}

func buildFundingClusterArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	a := p.HolderCluster
	if !a.Available {
		v := unavailableArm("Funding Cluster Detector", ModuleFundingClusterDetector, req, generatedAt, "At least three resolved holder wallets with parsed funding evidence are required; unavailable evidence is not LOW.")
		v.Signals["holder_cluster_analysis"] = a
		v.Signals["cluster_confidence"] = a.Confidence
		v.Signals["funding_recurrence"] = p.FundingRecurrence
		for _, limitation := range a.Limitations {
			v.Evidence = append(v.Evidence, "Limitation: "+limitation)
		}
		return v
	}
	s := armSignals(req, p, ModuleFundingClusterDetector)
	s["holder_cluster_analysis"] = a
	s["cluster_confidence"] = a.Confidence
	s["funding_recurrence"] = p.FundingRecurrence
	s["shared_funding_group_count"] = a.SharedFundingGroupCount
	s["largest_shared_funding_group"] = a.LargestSharedFundingGroup
	s["same_amount_group_count"] = a.SameAmountGroupCount
	s["common_exit_group_count"] = a.Flow.CommonExitGroupCount
	s["internal_transfer_count"] = a.Flow.InternalTransferCount
	s["circular_wallet_count"] = a.Flow.CircularWalletCount
	s["grade_effect"] = "none_at_arm_layer"
	e := append([]string{}, a.Findings...)
	for _, limitation := range a.Limitations {
		e = append(e, "Limitation: "+limitation)
	}
	v := evidenceArm("Funding Cluster Detector", ModuleFundingClusterDetector, req, 0, s, e, generatedAt)
	v.Verdict = a.Verdict
	v.Recommendation = "Inspect shared funders and direct transfer evidence; this arm does not issue a grade."
	return v
}

func buildSniperTimingArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	mintTiming := p.LiveRPC && p.TargetSignatureHistoryExhausted && p.TargetSignatureTimingObserved && p.RecentSignatureCount >= 2
	clusterTiming := p.HolderCluster.Available && p.HolderCluster.SynchronizedWalletCount >= 2
	if !mintTiming && !clusterTiming {
		reason := "Parsed holder acquisition slots or a complete mint-address signature history are required."
		if p.RecentSignatureCount >= 100 && !p.TargetSignatureHistoryExhausted {
			reason = "The latest 100 mint signatures are a truncated recent window and are not launch timing."
		}
		return unavailableArm("Sniper Timing Detector", ModuleSniperTimingDetector, req, generatedAt, reason)
	}
	s := armSignals(req, p, ModuleSniperTimingDetector)
	e := []string{}
	if mintTiming {
		s["recent_signature_count"] = p.RecentSignatureCount
		s["signature_window_seconds"] = p.SignatureWindowSeconds
		s["failed_signature_count"] = p.FailedSignatureCount
		s["mint_signature_history_exhausted"] = true
		e = append(e, fmt.Sprintf("Complete observed mint-address history: %d signatures across %d seconds.", p.RecentSignatureCount, p.SignatureWindowSeconds))
	}
	if clusterTiming {
		s["synchronized_holder_wallets"] = p.HolderCluster.SynchronizedWallets
		s["synchronized_wallet_count"] = p.HolderCluster.SynchronizedWalletCount
		s["synchronization_slot_spread"] = p.HolderCluster.SynchronizationSlotSpread
		e = append(e, fmt.Sprintf("%d resolved holder wallets acquired the token inside a %d-slot window.", p.HolderCluster.SynchronizedWalletCount, p.HolderCluster.SynchronizationSlotSpread))
	}
	s["scope_note"] = "Timing coordination is not sole proof of common ownership."
	return evidenceArm("Sniper Timing Detector", ModuleSniperTimingDetector, req, 0, s, e, generatedAt)
}

func buildProgramRelationArm(req SecurityRadarRequest, p radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	if !p.LiveRPC || !p.AccountExists || p.AccountOwner == "" {
		return unavailableArm("Program Relation Scan", ModuleProgramRelationScan, req, generatedAt, "Account owner evidence is required.")
	}
	s := armSignals(req, p, ModuleProgramRelationScan)
	s["account_owner"] = p.AccountOwner
	s["account_executable"] = p.AccountExecutable
	s["is_token_mint"] = p.IsTokenMint
	e := []string{
		fmt.Sprintf("Account owner program: %s.", p.AccountOwner),
		fmt.Sprintf("Executable account: %t.", p.AccountExecutable),
		fmt.Sprintf("Confirmed token mint: %t.", p.IsTokenMint),
	}
	return evidenceArm("Program Relation Scan", ModuleProgramRelationScan, req, 0, s, e, generatedAt)
}

// Compatibility adapter only. It deliberately cannot select a winning arm.
func buildFinalArm(req SecurityRadarRequest, _ []SecurityRadarVerdict, generatedAt string) SecurityRadarVerdict {
	v := unavailableArm("Final Verdict Engine", ModuleFinalVerdictEngine, req, generatedAt, "Final verdict is produced only by EvaluateUnifiedRadarVerdict.")
	v.Signals["verdict_source"] = "EvaluateUnifiedRadarVerdict"
	v.Signals["compatibility_adapter"] = true
	return v
}

func armSignals(req SecurityRadarRequest, p radarEvidenceProfile, moduleID string) map[string]any {
	s := map[string]any{
		"module_id":                 moduleID,
		"arm_evidence_available":    true,
		"real_onchain_evidence":     p.LiveRPC,
		"data_quality":              p.DataQuality,
		"evidence_status":           p.EvidenceStatus,
		"rpc_errors":                p.Errors,
		"grade_effect":              "none_at_arm_layer",
		"numeric_score_disabled":    true,
		"actor_ruleset_version":     ActorDefenseRulesetVersion,
		"unified_radar_ruleset":     UnifiedRadarRulesetVersion,
		"evidence_row_standard":     "signature, slot, timestamp, source, destination, amount, program, verification_status",
		"unverified_claims_allowed": false,
	}
	if sourceModule := arvisSourceModule(req.Mode); sourceModule != "" {
		s["source_module"] = sourceModule
	}
	return s
}

// risk is retained in the function signature only so older extension helpers can
// migrate independently. It is intentionally ignored: arms sign evidence, not
// grades or 0-100 scores.
func evidenceArm(module, moduleID string, req SecurityRadarRequest, risk int, signals map[string]any, evidence []string, generatedAt string) SecurityRadarVerdict {
	_ = risk
	if signals == nil {
		signals = map[string]any{}
	}
	signals["numeric_score_disabled"] = true
	signals["grade_effect"] = "none_at_arm_layer"
	signals["actor_ruleset_version"] = ActorDefenseRulesetVersion
	signals["unified_radar_ruleset"] = UnifiedRadarRulesetVersion
	signals["evidence_row_standard"] = "signature, slot, timestamp, source, destination, amount, program, verification_status"
	signals["unverified_claims_allowed"] = false
	if sourceModule := arvisSourceModule(req.Mode); sourceModule != "" {
		signals["source_module"] = sourceModule
	}
	v := SecurityRadarVerdict{
		Module: module, ModuleID: moduleID, Target: req.Target, Network: req.Network,
		Grade: "-", RiskIndex: 0, RiskLevel: "evidence_only",
		Verdict:        "Evidence collected; final grade is produced only by EvaluateUnifiedRadarVerdict.",
		Recommendation: "evaluate_unified_rules", Signals: signals, Evidence: evidence,
		GeneratedAt: generatedAt, RuleVersion: SecurityRadarRuleVersion, Signed: true,
	}
	v.Signature = signSecurityRadarVerdict(v.ModuleID, v.Target, v.Network, 0)
	return v
}

func unavailableArm(module, moduleID string, req SecurityRadarRequest, generatedAt, reason string) SecurityRadarVerdict {
	signals := map[string]any{
		"module_id": moduleID, "real_onchain_evidence": false,
		"arm_evidence_available": false, "evidence_status": "insufficient_evidence",
		"numeric_score_disabled": true, "grade_effect": "none_at_arm_layer",
		"actor_ruleset_version": ActorDefenseRulesetVersion, "unified_radar_ruleset": UnifiedRadarRulesetVersion,
		"evidence_row_standard":     "signature, slot, timestamp, source, destination, amount, program, verification_status",
		"unverified_claims_allowed": false,
	}
	if sourceModule := arvisSourceModule(req.Mode); sourceModule != "" {
		signals["source_module"] = sourceModule
	}
	return SecurityRadarVerdict{
		Module: module, ModuleID: moduleID, Target: req.Target, Network: req.Network,
		Grade: "-", RiskIndex: 0, RiskLevel: "unknown",
		Verdict: SecurityRadarInsufficientEvidenceMessage, Recommendation: "insufficient_evidence",
		Signals: signals, Evidence: []string{reason}, GeneratedAt: generatedAt,
		RuleVersion: SecurityRadarRuleVersion, Signed: false,
	}
}

func finalVerdictFromArm(_ SecurityRadarVerdict) SecurityRadarFinalVerdict {
	return arvisCompatibilityFinal()
}
