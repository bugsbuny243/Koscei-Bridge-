package handlers

import (
	"net/http"
	"strings"
	"time"
)

const transactionGuardV3AnalysisVersion = "v3-foundation-6"

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

func (h *Handler) finishTransactionGuardV3Response(w http.ResponseWriter, r *http.Request, input transactionGuardV2Request, requestID string, started time.Time, assessment transactionFirewallAssessment, programPolicy transactionGuardProgramPolicy, intentPolicy transactionGuardIntentPolicy, decoded transactionGuardDecodedTransaction, threatHistory transactionGuardThreatHistoryAnalysis, cpiFlow transactionGuardCPIFlowAnalysis, authoritySurface transactionGuardAuthoritySurfaceAnalysis, alertID string) {
	threatComplete := !threatHistory.Required || threatHistory.Complete
	cpiComplete := !cpiFlow.Required || cpiFlow.Complete
	authorityComplete := !authoritySurface.Required || authoritySurface.Complete
	guardComplete := assessment.SimulationOK && programPolicy.Complete && intentPolicy.Complete && decoded.Complete && threatComplete && cpiComplete && authorityComplete
	originalAction := assessment.Action
	assessment, enforcement := applyTransactionGuardEnforcementRequirement(input, requestID, assessment, guardComplete, time.Now().UTC())
	if originalAction == "allow" && assessment.Action != "allow" && alertID == "" {
		alertID = h.emitTransactionGuardAlert(r.Context(), requestID, input, assessment, programPolicy, intentPolicy)
	}
	explanation := buildTransactionGuardV3ExplanationWithAuthority(input.Wallet, assessment, decoded, threatHistory, cpiFlow, authoritySurface)
	h.saveTransactionGuardV2Report(r.Context(), requestID, input, assessment, programPolicy, intentPolicy, guardComplete, alertID)
	response := map[string]any{
		"ok":                         !guardProviderUnavailable(assessment),
		"request_id":                 requestID,
		"product":                    "Koschei Transaction Guard",
		"guard_version":              transactionGuardVersion,
		"analysis_version":           transactionGuardV3AnalysisVersion,
		"mode":                       transactionFirewallMode,
		"shadow_mode":                true,
		"enforcement_enabled":        enforcement.Configured,
		"billable":                   false,
		"network":                    input.Network,
		"encoding":                   input.Encoding,
		"wallet":                     strings.TrimSpace(input.Wallet),
		"transaction_fingerprint":    transactionFingerprint(input.Transaction),
		"action":                     assessment.Action,
		"risk_level":                 assessment.RiskLevel,
		"risk_index":                 assessment.RiskIndex,
		"summary":                    assessment.Summary,
		"findings":                   assessment.Findings,
		"guard_complete":             guardComplete,
		"automatic_decode_complete":  decoded.Complete,
		"automatic_balance_complete": decoded.AutomaticBalance.Complete,
		"automatic_balance_changes":  decoded.AutomaticBalance,
		"signed_ui_intent_complete":  decoded.SignedIntent.Complete,
		"signed_ui_intent":           decoded.SignedIntent,
		"threat_history_complete":    threatHistory.Complete,
		"threat_history":             threatHistory,
		"cpi_asset_flow_complete":    cpiFlow.Complete,
		"cpi_asset_flow":             cpiFlow,
		"authority_surface_complete": authoritySurface.Complete,
		"authority_surface":          authoritySurface,
		"pre_signing_explanation":    explanation,
		"decoded_transaction":        decoded,
		"program_policy":             programPolicy,
		"intent_policy":              intentPolicy,
		"alert_event_id":             alertID,
		"simulation": map[string]any{
			"ok": assessment.SimulationOK, "error": assessment.SimulationErr, "units_consumed": assessment.UnitsConsumed,
			"logs_count": len(assessment.Logs), "logs": assessment.Logs,
		},
		"latency_ms": time.Since(started).Milliseconds(),
		"warning":    "Koschei does not sign, submit or custody the transaction; an enforcement permit, when issued, only authorizes the exact fingerprint until expiry.",
	}
	attachTransactionGuardEnforcementResponse(response, enforcement)
	writeJSON(w, transactionGuardHTTPStatusWithEnforcement(assessment, enforcement), response)
}
