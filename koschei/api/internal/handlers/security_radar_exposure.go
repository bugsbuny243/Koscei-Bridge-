package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

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
	mode := strings.TrimSpace(r.URL.Query().Get("mode"))
	if mode == "" {
		mode = "exposure_report"
	}

	analysis := services.AnalyzeArvisRadars(services.SecurityRadarRequest{Target: target, Network: network, Mode: mode})
	bundle := services.EvidenceBackedSecurityRadarBundle(analysis.Bundle)
	final := services.ArvisFinalFromBundle(bundle)
	arms := services.ArvisArmsFromBundle(bundle)
	if !services.SecurityRadarHasLiveEvidence(bundle) || !final.Signed {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "real_data_unavailable", "message": services.SecurityRadarInsufficientEvidenceMessage,
			"target": target, "network": network, "final_verdict": final,
		})
		return
	}
	if h != nil && h.DB != nil {
		_ = h.saveSecurityRadarBundle(r.Context(), "", "exposure_report", bundle)
	}

	token2022Section := h.exposureToken2022Section(r.Context(), target, network)
	report := buildSecurityRadarExposureReport(target, network, final, arms, bundle.Metadata, token2022Section)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "report": report, "final_verdict": final, "arms": arms})
}

func buildSecurityRadarExposureReport(target, network string, final services.SecurityRadarFinalVerdict, arms []services.SecurityRadarVerdict, metadata map[string]any, token2022Section map[string]any) map[string]any {
	verified := 0
	unavailable := 0
	maxRisk := 0
	maxModule := ""
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
		if arm.RiskIndex > maxRisk {
			maxRisk = arm.RiskIndex
			maxModule = arm.ModuleID
		}
	}
	if token2022Section == nil {
		token2022Section = map[string]any{"module_id": "token_2022_extensions", "verified": false, "status": "not_collected"}
	}
	if tokenRisk, ok := token2022Section["risk_index"].(int); ok && tokenRisk > maxRisk {
		maxRisk = tokenRisk
		maxModule = "token_2022_extensions"
	}
	sections := map[string]any{
		"authority":             exposureSectionFromArm(arms, services.ModuleTokenAuthorityScanner, []string{"mint_authority_present", "freeze_authority_present", "account_owner"}),
		"holder_concentration":  exposureSectionFromArm(arms, services.ModuleHolderConcentration, []string{"largest_holder_percentage", "top_10_holder_percentage", "largest_accounts", "token_supply"}),
		"intelligence_graph":    exposureSectionFromArm(arms, services.ModuleIntelligenceGraph, []string{"account_owner", "latest_signature", "largest_accounts"}),
		"wallet_cluster":        exposureClusterAssessment(arms),
		"token_2022_extensions": token2022Section,
		"sniper_timing":         exposureSectionFromArm(arms, services.ModuleSniperTimingDetector, []string{"recent_signature_count", "signature_window_seconds", "failed_signature_count", "scope_note"}),
		"program_relation":      exposureSectionFromArm(arms, services.ModuleProgramRelationScan, []string{"account_owner", "program_id", "account_executable"}),
		"liquidity":             exposureSectionFromArm(arms, services.ModuleLiquidityMovement, []string{"pool", "reserve", "liquidity"}),
	}
	return map[string]any{
		"schema_version": "koschei-exposure-report-v1",
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"target":         target,
		"network":        network,
		"verdict":        final,
		"summary": map[string]any{
			"verified_arm_count":         verified,
			"unavailable_arm_count":      unavailable,
			"max_risk_index":             maxRisk,
			"max_risk_module":            maxModule,
			"token_2022_extension_count": exposureIntFromMap(token2022Section, "extension_count"),
			"token_2022_status":          token2022Section["status"],
			"rule_version":               final.RuleVersion,
			"signed":                     final.Signed,
		},
		"risk_taxonomy":     exposureRiskTaxonomy(arms, token2022Section),
		"sections":          sections,
		"evidence":          firstExposureEvidence(evidence, 10),
		"metadata":          metadata,
		"shareable_summary": exposureShareableSummary(target, final, arms, token2022Section),
		"evidence_policy":   exposureEvidencePolicy(),
		"disclaimer":        "This is evidence-backed on-chain risk analysis, not an accusation or financial advice.",
		"signature":         final.Signature,
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
		return map[string]any{"module_id": arm.ModuleID, "module": arm.Module, "risk_index": arm.RiskIndex, "risk_level": arm.RiskLevel, "verified": securityRadarArmVerified(arm), "signals": signals, "evidence": firstExposureEvidence(arm.Evidence, 5)}
	}
	return map[string]any{"module_id": moduleID, "verified": false, "evidence": []string{}}
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
		out = append(out, map[string]any{"module_id": arm.ModuleID, "risk_index": arm.RiskIndex, "risk_level": arm.RiskLevel, "verified": securityRadarArmVerified(arm), "label": exposureModuleLabel(arm.ModuleID)})
	}
	if token2022Section != nil {
		out = append(out, map[string]any{"module_id": "token_2022_extensions", "risk_index": token2022Section["risk_index"], "risk_level": token2022Section["risk_level"], "verified": token2022Section["verified"], "label": "Token-2022 extensions"})
	}
	return out
}

func exposureShareableSummary(target string, final services.SecurityRadarFinalVerdict, arms []services.SecurityRadarVerdict, token2022Section map[string]any) map[string]any {
	holder := exposureArmByModule(arms, services.ModuleHolderConcentration)
	authority := exposureArmByModule(arms, services.ModuleTokenAuthorityScanner)
	lines := []string{
		"Koschei ARVIS Exposure Report",
		"Target: " + target,
		fmt.Sprintf("Verdict: %s / %d/100", strings.ToUpper(firstNonEmptyString(final.RiskLevel, "watch")), final.RiskIndex),
	}
	if securityRadarArmVerified(holder) {
		lines = append(lines, fmt.Sprintf("Top holder: %v%%", holder.Signals["largest_holder_percentage"]))
		lines = append(lines, fmt.Sprintf("Top 10 holders: %v%%", holder.Signals["top_10_holder_percentage"]))
	}
	if securityRadarArmVerified(authority) {
		lines = append(lines, fmt.Sprintf("Mint authority present: %v", authority.Signals["mint_authority_present"]))
		lines = append(lines, fmt.Sprintf("Freeze authority present: %v", authority.Signals["freeze_authority_present"]))
	}
	if token2022Section != nil {
		if status := strings.TrimSpace(fmt.Sprint(token2022Section["status"])); status != "" {
			lines = append(lines, "Token-2022 status: "+status)
		}
		if count := exposureIntFromMap(token2022Section, "extension_count"); count > 0 {
			lines = append(lines, fmt.Sprintf("Token-2022 extensions: %d", count))
		}
	}
	lines = append(lines, "Not an accusation. Not financial advice. Evidence-first.")
	return map[string]any{"title": "Koschei ARVIS Exposure Report", "lines": lines, "hashtags": []string{"#KoscheiARVIS", "#Solana", "#Web3Security", "#OnChainSecurity", "#EvidenceFirst"}}
}

func exposureEvidencePolicy() map[string]any {
	return map[string]any{
		"no_evidence_no_claim":               true,
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
	if !arm.Signed || arm.Signals == nil {
		return false
	}
	for _, key := range []string{"verified_evidence", "real_onchain_evidence", "real_offchain_evidence"} {
		if value, _ := arm.Signals[key].(bool); value {
			return true
		}
	}
	return false
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

func firstExposureEvidence(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[:limit]
}
