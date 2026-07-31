package handlers

import (
	"net/http"
	"strings"
	"time"
)

const transactionGuardV3AnalysisVersion = "v3-foundation-7"

func applyTransactionGuardV3Decode(assessment transactionFirewallAssessment, intent *transactionGuardIntentPolicy, decoded transactionGuardDecodedTransaction, decodedFindings []transactionFirewallFinding) transactionFirewallAssessment {
	assessment.ProgramIDs = normalizeGuardProgramList(append(assessment.ProgramIDs, decoded.ProgramIDs...))
	assessment.Findings = removeTransactionGuardV3SupersededAuthorityFindings(assessment.Findings, decoded)
	assessment.Findings = mergeTransactionGuardV3Findings(assessment.Findings, decodedFindings)
	if intent != nil && (!decoded.Complete || decoded.AutomaticBalance.Requested && !decoded.AutomaticBalance.Complete || (decoded.SignedIntent.Requested || decoded.SignedIntent.Required) && !decoded.SignedIntent.Complete) {
		intent.Complete = false
	}
	return assessment
}

func removeTransactionGuardV3SupersededAuthorityFindings(existing []transactionFirewallFinding, decoded transactionGuardDecodedTransaction) []transactionFirewallFinding {
	remove := map[string]bool{}
	for _, operation := range decoded.TokenOperations {
		switch operation.Kind {
		case "approve", "approve_checked", "revoke":
			remove["delegate_approval"] = true
		case "set_authority":
			remove["authority_change"] = true
			if operation.AuthorityType != nil && *operation.AuthorityType == 8 {
				remove["permanent_delegate"] = true
			}
		case "initialize_permanent_delegate":
			remove["permanent_delegate"] = true
		case "initialize_transfer_hook", "update_transfer_hook":
			remove["transfer_hook"] = true
		}
	}
	if len(remove) == 0 {
		return existing
	}
	out := make([]transactionFirewallFinding, 0, len(existing))
	for _, finding := range existing {
		if !remove[finding.Code] {
			out = append(out, finding)
		}
	}
	return out
}

func mergeTransactionGuardV3Findings(existing, decoded []transactionFirewallFinding) []transactionFirewallFinding {
	seen := map[string]bool{}
	for _, finding := range existing {
		seen[finding.Code] = true
	}
	aliases := map[string]string{
		"decoded_delegate_approval": "delegate_approval",
		"decoded_authority_change":  "authority_change",
		"decoded_close_account":     "close_account",
		"decoded_freeze_account":    "freeze_account",
		"decoded_token_burn":        "token_burn",
	}
	out := append([]transactionFirewallFinding{}, existing...)
	for _, finding := range decoded {
		if seen[finding.Code] {
			continue
		}
		if alias := aliases[finding.Code]; alias != "" && seen[alias] {
			continue
		}
		seen[finding.Code] = true
		out = append(out, finding)
	}
	return out
}

func applyTransactionGuardV3PermitGate(assessment transactionFirewallAssessment, permit transactionGuardEnforcementPermit, findings []transactionFirewallFinding) (transactionFirewallAssessment, bool) {
	assessment.Findings = uniqueGuardV3Findings(append(assessment.Findings, findings...))
	action := strings.ToLower(strings.TrimSpace(assessment.Action))
	requiredForSigningDecision := permit.Required && (action == "allow" || action == "warn")
	if !requiredForSigningDecision || permit.Status == "issued" {
		return assessment, false
	}
	assessment.Action = "withhold"
	assessment.RiskLevel = "unknown"
	assessment.Summary = "Transaction Guard completed the evidence review but could not issue the required cryptographic wallet enforcement permit. Signing is withheld."
	return assessment, true
}

func transactionGuardV3PermitGateComplete(baseComplete bool, permit transactionGuardEnforcementPermit) bool {
	if !baseComplete {
		return false
	}
	if !permit.Required {
		return true
	}
	return permit.Status == "issued" || permit.Status == "not_issuable_for_decision"
}

func (h *Handler) finishTransactionGuardV3Response(w http.ResponseWriter, r *http.Request, input transactionGuardV2Request, requestID string, started time.Time, assessment transactionFirewallAssessment, programPolicy transactionGuardProgramPolicy, intentPolicy transactionGuardIntentPolicy, decoded transactionGuardDecodedTransaction, threatHistory transactionGuardThreatHistoryAnalysis, cpiFlow transactionGuardCPIFlowAnalysis, authoritySurface transactionGuardAuthoritySurfaceAnalysis, alertID string) {
	baseComplete := transactionGuardV3BaseEvidenceComplete(assessment, programPolicy, intentPolicy, decoded, threatHistory, cpiFlow, authoritySurface)
	permit, permitFindings := issueTransactionGuardV3EnforcementPermit(
		r, input, requestID, assessment, programPolicy, intentPolicy, decoded, threatHistory, cpiFlow, authoritySurface, baseComplete, time.Now().UTC(),
	)
	var permitGateChanged bool
	assessment, permitGateChanged = applyTransactionGuardV3PermitGate(assessment, permit, permitFindings)
	guardComplete := transactionGuardV3PermitGateComplete(baseComplete, permit)
	if permitGateChanged {
		alertID = h.emitStableTransactionGuardAlert(r.Context(), requestID, input, assessment, programPolicy, intentPolicy)
	}

	explanation := buildTransactionGuardV3ExplanationWithAuthority(input.Wallet, assessment, decoded, threatHistory, cpiFlow, authoritySurface)
	h.saveTransactionGuardV2Report(r.Context(), requestID, input, assessment, programPolicy, intentPolicy, guardComplete, alertID)
	response := map[string]any{
		"ok":                           !guardProviderUnavailable(assessment),
		"request_id":                   requestID,
		"product":                      "Koschei Transaction Guard",
		"guard_version":                transactionGuardVersion,
		"analysis_version":             transactionGuardV3AnalysisVersion,
		"mode":                         transactionFirewallMode,
		"shadow_mode":                  true,
		"enforcement_enabled":          false,
		"enforcement_permit_issued":    permit.Status == "issued",
		"enforcement_permit_complete":  permit.Complete,
		"enforcement_permit":           permit,
		"billable":                     false,
		"network":                      input.Network,
		"encoding":                     input.Encoding,
		"wallet":                       strings.TrimSpace(input.Wallet),
		"transaction_fingerprint":      transactionFingerprint(input.Transaction),
		"action":                       assessment.Action,
		"risk_level":                   assessment.RiskLevel,
		"risk_index":                   assessment.RiskIndex,
		"summary":                      assessment.Summary,
		"findings":                     assessment.Findings,
		"guard_complete":               guardComplete,
		"automatic_decode_complete":    decoded.Complete,
		"automatic_balance_complete":   decoded.AutomaticBalance.Complete,
		"automatic_balance_changes":    decoded.AutomaticBalance,
		"signed_ui_intent_complete":    decoded.SignedIntent.Complete,
		"signed_ui_intent":             decoded.SignedIntent,
		"threat_history_complete":      threatHistory.Complete,
		"threat_history":               threatHistory,
		"cpi_asset_flow_complete":      cpiFlow.Complete,
		"cpi_asset_flow":               cpiFlow,
		"authority_surface_complete":   authoritySurface.Complete,
		"authority_surface":            authoritySurface,
		"pre_signing_explanation":      explanation,
		"decoded_transaction":          decoded,
		"program_policy":               programPolicy,
		"intent_policy":                intentPolicy,
		"alert_event_id":               alertID,
		"simulation": map[string]any{
			"ok": assessment.SimulationOK, "error": assessment.SimulationErr, "units_consumed": assessment.UnitsConsumed,
			"logs_count": len(assessment.Logs), "logs": assessment.Logs,
		},
		"latency_ms": time.Since(started).Milliseconds(),
		"warning":    "Koschei remains no-custody and does not sign or submit transactions. Wallets or extensions may enforce an issued permit against the exact transaction fingerprint.",
	}
	writeJSON(w, guardHTTPStatus(assessment), response)
}
