package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const investigationAcceptanceVersion = "koschei-investigation-acceptance-v1"

type InvestigationAcceptanceFinding struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Section string `json:"section,omitempty"`
}

type InvestigationAcceptanceMetrics struct {
	CapabilityTotal          int      `json:"capability_total"`
	CompletedCollectors      int      `json:"completed_collectors"`
	EvidenceProducing        int      `json:"evidence_producing"`
	NotApplicable            int      `json:"not_applicable"`
	EvidencePending          int      `json:"evidence_pending"`
	SourceUnavailable        int      `json:"source_unavailable"`
	InsufficientEvidence     int      `json:"insufficient_evidence"`
	ConcreteSignals          int      `json:"concrete_signals"`
	ReferenceCompleteSignals int      `json:"reference_complete_signals"`
	LiveWalletWindows        int      `json:"live_wallet_windows"`
	CompletedWalletWindows   int      `json:"completed_wallet_windows"`
	LiveTransactions         int      `json:"live_transactions"`
	CriticalGaps             []string `json:"critical_gaps"`
}

type InvestigationCallerParity struct {
	Passed     bool              `json:"passed"`
	Projection string            `json:"projection"`
	Hashes     map[string]string `json:"hashes"`
}

type InvestigationAcceptanceResult struct {
	Version      string                           `json:"version"`
	Status       string                           `json:"status"`
	Profile      string                           `json:"profile"`
	Target       string                           `json:"target"`
	Expected     string                           `json:"expected_target"`
	Ruleset      string                           `json:"ruleset,omitempty"`
	Signature    string                           `json:"signature,omitempty"`
	GeneratedAt  time.Time                        `json:"generated_at"`
	Metrics      InvestigationAcceptanceMetrics   `json:"metrics"`
	CallerParity InvestigationCallerParity        `json:"caller_parity"`
	Blockers     []InvestigationAcceptanceFinding `json:"blockers"`
	Warnings     []InvestigationAcceptanceFinding `json:"warnings"`
}

type investigationAcceptanceRequirements struct {
	MinCompleted         int
	MinEvidenceProducing int
	MinConcreteSignals   int
	RequireLiveWindow    bool
}

func investigationAcceptanceProfile(value string) (string, investigationAcceptanceRequirements) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "bonding_curve", "new_token", "low_activity":
		return value, investigationAcceptanceRequirements{MinCompleted: 8, MinEvidenceProducing: 8, MinConcreteSignals: 14, RequireLiveWindow: true}
	case "dex_traded", "high_concentration", "low_concentration", "creator_sell", "lp_movement", "old_token", "high_activity":
		return value, investigationAcceptanceRequirements{MinCompleted: 10, MinEvidenceProducing: 10, MinConcreteSignals: 16, RequireLiveWindow: true}
	default:
		return "standard_traded_token", investigationAcceptanceRequirements{MinCompleted: 10, MinEvidenceProducing: 10, MinConcreteSignals: 16, RequireLiveWindow: true}
	}
}

func evaluateInvestigationAcceptance(report map[string]any, expectedTarget, profile string) InvestigationAcceptanceResult {
	profile, requirements := investigationAcceptanceProfile(profile)
	result := InvestigationAcceptanceResult{
		Version:     investigationAcceptanceVersion,
		Status:      "pass",
		Profile:     profile,
		Target:      strings.TrimSpace(dossierString(report["target"])),
		Expected:    strings.TrimSpace(expectedTarget),
		GeneratedAt: time.Now().UTC(),
		Blockers:    []InvestigationAcceptanceFinding{},
		Warnings:    []InvestigationAcceptanceFinding{},
	}

	if dossierString(report["schema_version"]) != unifiedInvestigationSchemaVersion {
		result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "schema_mismatch", Section: "report", Message: "Unified investigation schema is missing or unexpected."})
	}
	if result.Expected == "" || !strings.EqualFold(result.Target, result.Expected) {
		result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "target_mismatch", Section: "report", Message: fmt.Sprintf("Requested target %q does not match report target %q.", result.Expected, result.Target)})
	}

	final := dossierMap(report["final_verdict"])
	result.Ruleset = dossierString(final["ruleset_version"])
	result.Signature = dossierString(final["signature"])
	if dossierBool(final["signed"]) && result.Signature == "" {
		result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "signed_verdict_missing_signature", Section: "final_verdict", Message: "Signed verdict has no signature."})
	}
	if result.Ruleset == "" {
		result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "ruleset_missing", Section: "final_verdict", Message: "Ruleset version is missing."})
	}

	coverage := dossierMap(report["investigation_coverage"])
	result.Metrics.CapabilityTotal = dossierInt(coverage["capability_total"])
	result.Metrics.CompletedCollectors = dossierInt(coverage["completed"])
	result.Metrics.EvidenceProducing = dossierInt(coverage["evidence_producing"])
	result.Metrics.NotApplicable = dossierInt(coverage["not_applicable"])
	result.Metrics.EvidencePending = dossierInt(coverage["evidence_pending"])
	result.Metrics.SourceUnavailable = dossierInt(coverage["source_unavailable"])
	result.Metrics.InsufficientEvidence = dossierInt(coverage["insufficient_evidence"])
	result.Metrics.CriticalGaps = dossierStrings(coverage["critical_gaps"])
	if result.Metrics.CapabilityTotal != 14 {
		result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "capability_contract_mismatch", Section: "investigation_coverage", Message: fmt.Sprintf("Expected 14 capabilities, got %d.", result.Metrics.CapabilityTotal)})
	}

	rows := buildDossierSignalRows(report)
	for _, row := range rows {
		if row.State == signalStateVerified || row.State == signalStateObserved || row.State == signalStateNotApplicable {
			result.Metrics.ConcreteSignals++
		}
		if signalStateIsEvidence(row.State) {
			def, registered := signalDefinitionByID(row.ID)
			if registered && def.RequireRefs {
				if dossierRefsPresent(row.Refs) {
					result.Metrics.ReferenceCompleteSignals++
				} else {
					result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "populated_signal_missing_reference", Section: row.ID, Message: "Verified or observed signal has no wallet, account, signature, slot or evidence key."})
				}
			}
		}
	}
	if len(rows) != len(signalRegistry) {
		result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "signal_contract_mismatch", Section: "verdict_card", Message: fmt.Sprintf("Expected %d registered technical signals, got %d.", len(signalRegistry), len(rows))})
	}

	live := dossierMap(report["full_scan_live_evidence"])
	liveMint := strings.TrimSpace(dossierString(live["mint"]))
	if liveMint != "" && !strings.EqualFold(liveMint, result.Target) {
		result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "live_evidence_target_mismatch", Section: "full_scan_live_evidence", Message: fmt.Sprintf("Live evidence mint %q does not match report target %q.", liveMint, result.Target)})
	}
	walletCoverage := dossierSlice(live["wallet_coverage"])
	result.Metrics.LiveWalletWindows = len(walletCoverage)
	for _, item := range walletCoverage {
		status := strings.ToLower(dossierString(dossierMap(item)["status"]))
		if status == "complete" || status == "complete_no_relevant_token_delta" || status == "complete_no_successful_signatures" {
			result.Metrics.CompletedWalletWindows++
		}
	}
	transactions := dossierSlice(live["transactions"])
	result.Metrics.LiveTransactions = len(transactions)
	for index, item := range transactions {
		row := dossierMap(item)
		missing := []string{}
		if dossierString(row["signature"]) == "" {
			missing = append(missing, "signature")
		}
		if dossierInt64(row["slot"]) <= 0 {
			missing = append(missing, "slot")
		}
		if dossierString(row["wallet"]) == "" {
			missing = append(missing, "wallet")
		}
		if dossierString(row["direction"]) == "" {
			missing = append(missing, "direction")
		}
		if dossierString(row["evidence_key"]) == "" {
			missing = append(missing, "evidence_key")
		}
		if len(missing) > 0 {
			result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "live_transaction_incomplete", Section: fmt.Sprintf("full_scan_live_evidence.transactions[%d]", index), Message: "Live transaction row is missing: " + strings.Join(missing, ", ")})
		}
	}

	result.CallerParity = investigationCallerParity(report)
	if !result.CallerParity.Passed {
		result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "caller_parity_failed", Section: "technical_projection", Message: "Public, owner and API technical projections differ."})
	}

	if result.Metrics.CompletedCollectors < requirements.MinCompleted {
		result.Warnings = append(result.Warnings, InvestigationAcceptanceFinding{Code: "completed_collector_floor_missed", Section: "investigation_coverage", Message: fmt.Sprintf("Completed collectors %d/%d; profile requires at least %d.", result.Metrics.CompletedCollectors, result.Metrics.CapabilityTotal, requirements.MinCompleted)})
	}
	if result.Metrics.EvidenceProducing < requirements.MinEvidenceProducing {
		result.Warnings = append(result.Warnings, InvestigationAcceptanceFinding{Code: "evidence_collector_floor_missed", Section: "investigation_coverage", Message: fmt.Sprintf("Evidence-producing collectors %d/%d; profile requires at least %d.", result.Metrics.EvidenceProducing, result.Metrics.CapabilityTotal, requirements.MinEvidenceProducing)})
	}
	if result.Metrics.ConcreteSignals < requirements.MinConcreteSignals {
		result.Warnings = append(result.Warnings, InvestigationAcceptanceFinding{Code: "concrete_signal_floor_missed", Section: "verdict_card", Message: fmt.Sprintf("Concrete signals %d/%d; profile requires at least %d.", result.Metrics.ConcreteSignals, len(signalRegistry), requirements.MinConcreteSignals)})
	}
	if requirements.RequireLiveWindow && strings.EqualFold(dossierString(live["status"]), "not_requested") {
		result.Blockers = append(result.Blockers, InvestigationAcceptanceFinding{Code: "live_window_not_requested", Section: "full_scan_live_evidence", Message: "Full investigation did not request the bounded live transaction window."})
	}
	if len(result.Metrics.CriticalGaps) > 0 {
		result.Warnings = append(result.Warnings, InvestigationAcceptanceFinding{Code: "critical_coverage_gaps", Section: "investigation_coverage", Message: "Critical gaps: " + strings.Join(result.Metrics.CriticalGaps, ", ")})
	}

	if len(result.Blockers) > 0 {
		result.Status = "fail"
	} else if len(result.Warnings) > 0 {
		result.Status = "partial"
	}
	return result
}

func investigationCallerParity(report map[string]any) InvestigationCallerParity {
	projection := unifiedInvestigationTechnicalProjection(report)
	owner, _ := json.Marshal(projection)
	publicEnvelope := map[string]any{"investigation_report": report}
	public, _ := json.Marshal(unifiedInvestigationTechnicalProjection(publicEnvelope["investigation_report"].(map[string]any)))
	apiResult := customerTokenScanResult{InvestigationReport: report}
	api, _ := json.Marshal(unifiedInvestigationTechnicalProjection(apiResult.InvestigationReport))
	hashes := map[string]string{
		"owner":  acceptanceSHA256(owner),
		"public": acceptanceSHA256(public),
		"api":    acceptanceSHA256(api),
	}
	return InvestigationCallerParity{Passed: string(owner) == string(public) && string(owner) == string(api), Projection: "unified_investigation_technical_projection", Hashes: hashes}
}

func acceptanceSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func dossierInt(value any) int { return int(dossierInt64(value)) }

func dossierInt64(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	default:
		return 0
	}
}
