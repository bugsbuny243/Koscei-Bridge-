package handlers

import (
	"net/http"
	"strings"
	"time"
)

const transactionGuardV3AnalysisVersion = "v3-foundation-5"

func applyTransactionGuardV3Decode(assessment transactionFirewallAssessment, intent *transactionGuardIntentPolicy, decoded transactionGuardDecodedTransaction, decodedFindings []transactionFirewallFinding) transactionFirewallAssessment {
	assessment.ProgramIDs = normalizeGuardProgramList(append(assessment.ProgramIDs, decoded.ProgramIDs...))
	assessment.Findings = mergeTransactionGuardV3Findings(assessment.Findings, decodedFindings)
	if intent != nil && (!decoded.Complete || decoded.AutomaticBalance.Requested && !decoded.AutomaticBalance.Complete || (decoded.SignedIntent.Requested || decoded.SignedIntent.Required) && !decoded.SignedIntent.Complete) {
		intent.Complete = false
	}
	return assessment
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

func (h *Handler) finishTransactionGuardV3Response(w http.ResponseWriter, r *http.Request, input transactionGuardV2Request, requestID string, started time.Time, assessment transactionFirewallAssessment, programPolicy transactionGuardProgramPolicy, intentPolicy transactionGuardIntentPolicy, decoded transactionGuardDecodedTransaction, threatHistory transactionGuardThreatHistoryAnalysis, cpiFlow transactionGuardCPIFlowAnalysis, alertID string) {
	threatComplete := !threatHistory.Required || threatHistory.Complete
	cpiComplete := !cpiFlow.Required || cpiFlow.Complete
	guardComplete := assessment.SimulationOK && programPolicy.Complete && intentPolicy.Complete && decoded.Complete && threatComplete && cpiComplete
	explanation := buildTransactionGuardV3Explanation(input.Wallet, assessment, decoded, threatHistory, cpiFlow)
	h.saveTransactionGuardV2Report(r.Context(), requestID, input, assessment, programPolicy, intentPolicy, guardComplete, alertID)
	response := map[string]any{
		"ok":                         !guardProviderUnavailable(assessment),
		"request_id":                 requestID,
		"product":                    "Koschei Transaction Guard",
		"guard_version":              transactionGuardVersion,
		"analysis_version":           transactionGuardV3AnalysisVersion,
		"mode":                       transactionFirewallMode,
		"shadow_mode":                true,
		"enforcement_enabled":        false,
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
		"warning":    "Shadow mode only: Koschei does not sign, submit or custody this transaction.",
	}
	writeJSON(w, guardHTTPStatus(assessment), response)
}
