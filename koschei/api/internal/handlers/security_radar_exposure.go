package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/decision"
	"koschei/api/internal/services"
)

const exposureReportExecutionMode = "exposure_report_stored_only"

func (h *Handler) SecurityRadarExposureReport(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(firstNonEmptyString(r.URL.Query().Get("target"), r.URL.Query().Get("address"), r.URL.Query().Get("mint")))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}
	requestedMode := strings.TrimSpace(r.URL.Query().Get("mode"))
	if requestedMode == "" {
		requestedMode = "exposure_report"
	}

	// Exposure is a bounded Professional read surface. Reuse the canonical
	// investigation core so holder/market/LP evidence cannot drift from the
	// paid investigation path, while stored_only prevents this read from
	// starting the broader live actor/funding investigation.
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	assembly := h.buildUnifiedInvestigationReport(ctx, target, network, exposureReportExecutionMode)
	analysisSummary := attachCustomerAnalysisSummary(&assembly)
	bundle := services.EvidenceBackedSecurityRadarBundle(assembly.Core.Bundle)
	arms := services.ArvisArmsFromBundle(bundle)
	if len(arms) == 0 {
		arms = assembly.Core.Arms
	}
	canonicalDecision := decision.FromUnifiedRadar(assembly.UnifiedVerdict.Grade, assembly.UnifiedVerdict.Verdict)
	if !services.SecurityRadarHasLiveEvidence(bundle) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "real_data_unavailable", "message": services.SecurityRadarInsufficientEvidenceMessage,
			"target": target, "network": network, "final_verdict": assembly.UnifiedVerdict,
			"decision": canonicalDecision, "arms": arms,
		})
		return
	}
	if h != nil && h.DB != nil {
		_ = h.saveSecurityRadarBundle(ctx, "", "exposure_report", bundle)
	}

	token2022Section := h.exposureToken2022Section(ctx, target, network)
	report := buildSecurityRadarExposureReport(
		target, network, assembly.UnifiedVerdict, canonicalDecision, arms, bundle.Metadata,
		token2022Section, analysisSummary, requestedMode,
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"report":           report,
		"final_verdict":    assembly.UnifiedVerdict,
		"decision":         canonicalDecision,
		"analysis_summary": analysisSummary,
		"arms":             arms,
	})
}

func buildSecurityRadarExposureReport(target, network string, final services.UnifiedRadarVerdict, canonicalDecision decision.Contract, arms []services.SecurityRadarVerdict, metadata map[string]any, token2022Section map[string]any, analysisSummary map[string]any, requestedMode string) map[string]any {
	verified := 0
	unavailable := 0
	evidence := []string{}
	for _, arm := range arms {
		if securityRadarArmVerified(arm) {
			verified++
			if len(evidence) < 10 {
				evidence = append(evidence, arm.Evidence...)
			}
		} else {
			unavailable++
		}
	}
	if token2022Section == nil {
		token2022Section = map[string]any{"module_id": "token_2022_extensions", "verified": false, "status": "not_collected"}
	}
	sections := map[string]any{
		"authority":             exposureSectionFromArm(arms, services.ModuleTokenAuthorityScanner, []string{"mint_authority_present", "freeze_authority_present", "account_owner", "execution_status", "evidence_status"}),
		"holder_concentration":  exposureSectionFromArm(arms, services.ModuleHolderConcentration, []string{"largest_holder_percentage", "top_10_holder_percentage", "largest_accounts", "token_supply", "execution_status", "evidence_status"}),
		"intelligence_graph":    exposureSectionFromArm(arms, services.ModuleIntelligenceGraph, []string{"account_owner", "latest_signature", "largest_accounts", "execution_status", "evidence_status"}),
		"wallet_cluster":        exposureClusterAssessment(arms),
		"token_2022_extensions": token2022Section,
		"sniper_timing":         exposureSectionFromArm(arms, services.ModuleSniperTimingDetector, []string{"recent_signature_count", "signature_window_seconds", "failed_signature_count", "scope_note", "execution_status", "evidence_status"}),
		"program_relation":      exposureSectionFromArm(arms, services.ModuleProgramRelationScan, []string{"account_owner", "program_id", "account_executable", "execution_status", "evidence_status"}),
		"liquidity":             exposureSectionFromArm(arms, services.ModuleLiquidityMovement, exposureLiquiditySignalKeys()),
	}
	return map[string]any{
		"schema_version":   "koschei-exposure-report-v2",
		"generated_at":     time.Now().UTC().Format(time.RFC3339),
		"target":           target,
		"network":          network,
		"requested_mode":   requestedMode,
		"execution_mode":   exposureReportExecutionMode,
		"verdict":          final,
		"decision":         canonicalDecision,
		"analysis_summary": analysisSummary,
		"summary": map[string]any{
			"verified_arm_count":           verified,
			"unavailable_arm_count":        unavailable,
			"token_2022_extension_count":   exposureIntFromMap(token2022Section, "extension_count"),
			"token_2022_status":            token2022Section["status"],
			"grade":                        final.Grade,
			"verdict":                      final.Verdict,
			"ruleset_version":              final.RulesetVersion,
			"signed":                       final.Signed,
			"action":                       canonicalDecision.Action,
			"withhold_reason":              canonicalDecision.WithholdReason,
			"numeric_final_score_disabled": true,
		},
		"risk_taxonomy":     exposureRiskTaxonomy(arms, token2022Section),
		"sections":          sections,
		"evidence":          firstExposureEvidence(evidence, 10),
		"metadata":          metadata,
		"shareable_summary": exposureShareableSummary(target, final, canonicalDecision, arms, token2022Section),
		"evidence_policy":   exposureEvidencePolicy(),
		"disclaimer":        "This is evidence-backed on-chain risk analysis, not an accusation or financial advice.",
		"signature":         final.Signature,
	}
}

func exposureLiquiditySignalKeys() []string {
	return []string{
		"execution_status", "evidence_status", "lp_control",
		"pool_address", "pool_program", "pool_type", "control_model", "position_model", "pool_creator", "creator_wallet", "canonical_pool",
		"lp_mint", "lp_supply", "lp_supply_source", "lp_lock_status",
		"token_vault", "quote_vault", "read_slot", "token_reserve", "quote_reserve", "effective_quote_reserve", "reserve_liquidity_usd", "reserve_value_source",
		"burned_share_pct", "creator_lp_share_pct", "dominant_lp_owner", "dominant_lp_token_account", "dominant_lp_share_pct", "dominant_lp_classification", "creator_relation",
		"locked_lp_amount", "locked_lp_share_pct", "locked_lp_token_accounts", "locked_lp_authority_accounts", "locked_position_count", "locked_position_liquidity_raw", "locked_positions", "locked_until",
		"movement_status", "liquidity_movement_count", "liquidity_movement_signatures", "liquidity_movement_slots", "liquidity_movement_actors", "liquidity_movement_kinds", "liquidity_movements",
		"liquidity_movement_transaction_verified", "movement_evidence_status", "reserve_snapshot_verified", "evidence_keys",
	}
}

func exposureSectionFromArm(arms []services.SecurityRadarVerdict, moduleID string, signalKeys []string) map[string]any {
	for _, arm := range arms {
		if arm.ModuleID != moduleID {
			continue
		}
		signals := map[string]any{}
		for _, key := range signalKeys {
			if value, ok := arm.Signals[key]; ok {
				signals[key] = value
			}
		}
		return map[string]any{
			"module_id": arm.ModuleID, "module": arm.Module,
			"risk_index": arm.RiskIndex, "risk_level": arm.RiskLevel,
			"verified": securityRadarArmVerified(arm), "signals": signals,
			"evidence": firstExposureEvidence(arm.Evidence, 8),
		}
	}
	return map[string]any{"module_id": moduleID, "verified": false, "signals": map[string]any{}, "evidence": []string{}}
}

func exposureClusterAssessment(arms []services.SecurityRadarVerdict) map[string]any {
	funding := exposureArmByModule(arms, services.ModuleFundingClusterDetector)
	creator := exposureArmByModule(arms, services.ModuleCreatorLinkAnalysis)
	graph := exposureArmByModule(arms, services.ModuleIntelligenceGraph)
	confirmed := securityRadarArmVerified(funding) || securityRadarArmVerified(creator)
	status := "not_confirmed"
	if confirmed {
		status = "evidence_present"
	} else if securityRadarArmVerified(graph) {
		status = "relationship_inputs_partial"
	}
	return map[string]any{
		"status":                        status,
		"confirmed_same_wallet_cluster": confirmed,
		"safe_public_language":          "Possible linked-wallet cluster is reported only when funding, creator-link or parsed transaction evidence is verified. Otherwise ARVIS reports holder concentration without claiming common ownership.",
		"required_evidence":             []string{"parsed funding transactions", "shared funder or creator relation", "same-slot or coordinated timing evidence", "token-account owner mapping"},
		"funding_cluster":               exposureCompactArm(funding),
		"creator_link":                  exposureCompactArm(creator),
		"graph_context":                 exposureCompactArm(graph),
	}
}

func exposureRiskTaxonomy(arms []services.SecurityRadarVerdict, token2022Section map[string]any) []map[string]any {
	modules := []string{services.ModuleTokenAuthorityScanner, services.ModuleHolderConcentration, services.ModuleLiquidityMovement, services.ModuleFundingClusterDetector, services.ModuleSniperTimingDetector, services.ModuleClaimSurfaceRisk, services.ModuleProgramRelationScan}
	out := []map[string]any{}
	for _, moduleID := range modules {
		arm := exposureArmByModule(arms, moduleID)
		if arm.ModuleID == "" {
			continue
		}
		out = append(out, map[string]any{
			"module_id": arm.ModuleID, "risk_index": arm.RiskIndex, "risk_level": arm.RiskLevel,
			"verified": securityRadarArmVerified(arm), "label": exposureModuleLabel(arm.ModuleID),
			"numeric_final_score_authority": false,
		})
	}
	if token2022Section != nil {
		out = append(out, map[string]any{"module_id": "token_2022_extensions", "risk_index": token2022Section["risk_index"], "risk_level": token2022Section["risk_level"], "verified": token2022Section["verified"], "label": "Token-2022 extensions", "numeric_final_score_authority": false})
	}
	return out
}

func exposureShareableSummary(target string, final services.UnifiedRadarVerdict, canonicalDecision decision.Contract, arms []services.SecurityRadarVerdict, token2022Section map[string]any) map[string]any {
	holder := exposureArmByModule(arms, services.ModuleHolderConcentration)
	liquidity := exposureArmByModule(arms, services.ModuleLiquidityMovement)
	lines := []string{
		"Koschei ARVIS Exposure Report",
		"Target: " + target,
		"Action: " + strings.ToUpper(string(canonicalDecision.Action)),
		"Grade: " + firstNonEmptyString(final.Grade, "-"),
	}
	if canonicalDecision.WithholdReason != "" {
		lines = append(lines, "Withhold reason: "+canonicalDecision.WithholdReason)
	}
	if securityRadarArmVerified(holder) {
		lines = append(lines, fmt.Sprintf("Top holder: %v%%", holder.Signals["largest_holder_percentage"]))
		lines = append(lines, fmt.Sprintf("Top 10 holders: %v%%", holder.Signals["top_10_holder_percentage"]))
	}
	if securityRadarArmVerified(liquidity) {
		if pool := strings.TrimSpace(fmt.Sprint(liquidity.Signals["pool_address"])); pool != "" {
			lines = append(lines, "Liquidity pool: "+pool)
		}
		if slot := exposureInt64FromMap(liquidity.Signals, "read_slot"); slot > 0 {
			lines = append(lines, fmt.Sprintf("Reserve evidence slot: %d", slot))
		}
		if count := exposureIntFromMap(liquidity.Signals, "liquidity_movement_count"); count > 0 {
			lines = append(lines, fmt.Sprintf("Verified liquidity movement rows: %d", count))
		}
	}
	if token2022Section != nil {
		if status := strings.TrimSpace(fmt.Sprint(token2022Section["status"])); status != "" {
			lines = append(lines, "Token-2022 status: "+status)
		}
	}
	lines = append(lines, "No numeric final score. Missing evidence is not a safety signal.")
	return map[string]any{"title": "Koschei ARVIS Exposure Report", "lines": lines, "hashtags": []string{"#KoscheiARVIS", "#Solana", "#Web3Security", "#OnChainSecurity", "#EvidenceFirst"}}
}

func exposureEvidencePolicy() map[string]any {
	return map[string]any{
		"no_evidence_no_claim":               true,
		"missing_evidence_is_not_safe":       true,
		"numeric_final_score_disabled":       true,
		"unsigned_result_is_not_approval":    true,
		"same_wallet_cluster_claim_requires": []string{"owner mapping", "funding relation", "creator relation or parsed coordinated transaction evidence"},
		"safe_terms":                         []string{"risk signal", "holder concentration", "exit-liquidity risk", "possible linked-wallet cluster", "Token-2022 extension behavior"},
		"blocked_terms_without_proof":        []string{"scam", "rug", "fraud", "same owner controls all wallets"},
	}
}

func exposureArmByModule(arms []services.SecurityRadarVerdict, moduleID string) services.SecurityRadarVerdict {
	for _, arm := range arms {
		if arm.ModuleID == moduleID {
			return arm
		}
	}
	return services.SecurityRadarVerdict{}
}

func exposureCompactArm(arm services.SecurityRadarVerdict) map[string]any {
	if arm.ModuleID == "" {
		return map[string]any{"verified": false}
	}
	return map[string]any{"module_id": arm.ModuleID, "risk_index": arm.RiskIndex, "risk_level": arm.RiskLevel, "verified": securityRadarArmVerified(arm), "evidence": firstExposureEvidence(arm.Evidence, 3)}
}

func exposureModuleLabel(moduleID string) string {
	switch moduleID {
	case services.ModuleTokenAuthorityScanner:
		return "authority risk"
	case services.ModuleHolderConcentration:
		return "holder concentration"
	case services.ModuleLiquidityMovement:
		return "liquidity / exit risk"
	case services.ModuleFundingClusterDetector:
		return "wallet cluster"
	case services.ModuleSniperTimingDetector:
		return "sniper timing"
	case services.ModuleClaimSurfaceRisk:
		return "claim surface"
	case services.ModuleProgramRelationScan:
		return "program relation"
	default:
		return moduleID
	}
}

func securityRadarArmVerified(arm services.SecurityRadarVerdict) bool {
	return services.SecurityRadarVerdictHasVerifiedEvidence(arm)
}

func exposureIntFromMap(values map[string]any, key string) int {
	if values == nil {
		return 0
	}
	switch value := values[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case float32:
		return int(value)
	default:
		return 0
	}
}

func exposureInt64FromMap(values map[string]any, key string) int64 {
	if values == nil {
		return 0
	}
	switch value := values[key].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	case float32:
		return int64(value)
	default:
		return 0
	}
}

func firstExposureEvidence(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return append([]string{}, values...)
	}
	return append([]string{}, values[:limit]...)
}
