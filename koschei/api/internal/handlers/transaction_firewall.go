package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const (
	transactionFirewallProduct = "Koschei Transaction Firewall"
	transactionFirewallMode    = "shadow"
	maxFirewallTransactionSize = 4096
	maxFirewallLogs            = 200
)

type transactionFirewallFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
	Score    int    `json:"-"`
}

type transactionFirewallAssessment struct {
	Action        string                       `json:"action"`
	RiskLevel     string                       `json:"risk_level"`
	RiskIndex     int                          `json:"risk_index"`
	Summary       string                       `json:"summary"`
	Findings      []transactionFirewallFinding `json:"findings"`
	ProgramIDs    []string                     `json:"program_ids"`
	Logs          []string                     `json:"logs"`
	UnitsConsumed int64                        `json:"units_consumed"`
	SimulationOK  bool                         `json:"simulation_ok"`
	SimulationErr any                          `json:"simulation_error,omitempty"`
}

var firewallProgramInvokePattern = regexp.MustCompile(`(?i)^Program ([1-9A-HJ-NP-Za-km-z]{32,44}) invoke`)

func (h *Handler) transactionFirewallSimulate(w http.ResponseWriter, r *http.Request, input shieldPreflightRequest) {
	if !transactionFirewallEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":      false,
			"code":    "transaction_firewall_disabled",
			"message": "Transaction Firewall is disabled by configuration.",
		})
		return
	}

	transaction := strings.TrimSpace(input.Transaction)
	encoding := strings.ToLower(strings.TrimSpace(input.Encoding))
	if encoding == "" {
		encoding = "base64"
	}
	if err := validateFirewallTransaction(transaction, encoding); err != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "invalid_transaction", "message": err})
		return
	}

	network := strings.TrimSpace(input.Network)
	if network == "" {
		network = "solana-mainnet"
	}
	if network != "solana-mainnet" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":      false,
			"code":    "unsupported_network",
			"message": "Transaction Firewall currently supports solana-mainnet only.",
		})
		return
	}

	requestID := shieldRequestID(transactionFingerprint(transaction), network, time.Now())
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	simulation, err := services.SolanaSimulateTransaction(ctx, os.Getenv("SOLANA_RPC_URL"), transaction, encoding)
	if err != nil {
		assessment := transactionFirewallAssessment{
			Action:        "withhold",
			RiskLevel:     "unknown",
			RiskIndex:     0,
			Summary:       "Simulation provider is unavailable; no safe decision was produced.",
			Findings:      []transactionFirewallFinding{},
			ProgramIDs:    []string{},
			Logs:          []string{},
			SimulationOK:  false,
			SimulationErr: map[string]any{"code": "rpc_unavailable", "message": publicFirewallError(err.Error())},
		}
		h.saveTransactionFirewallReport(r.Context(), requestID, transaction, network, encoding, assessment)
		writeJSON(w, http.StatusServiceUnavailable, transactionFirewallResponse(requestID, transaction, network, encoding, input.Wallet, time.Since(started), assessment))
		return
	}

	assessment := assessTransactionSimulation(simulation)
	h.saveTransactionFirewallReport(r.Context(), requestID, transaction, network, encoding, assessment)
	writeJSON(w, http.StatusOK, transactionFirewallResponse(requestID, transaction, network, encoding, input.Wallet, time.Since(started), assessment))
}

func transactionFirewallResponse(requestID, transaction, network, encoding, wallet string, latency time.Duration, assessment transactionFirewallAssessment) map[string]any {
	return map[string]any{
		"ok":                      assessment.SimulationOK,
		"request_id":              requestID,
		"product":                 transactionFirewallProduct,
		"mode":                    transactionFirewallMode,
		"shadow_mode":             true,
		"enforcement_enabled":     false,
		"billable":                false,
		"network":                 network,
		"encoding":                encoding,
		"wallet":                  strings.TrimSpace(wallet),
		"transaction_fingerprint": transactionFingerprint(transaction),
		"action":                  assessment.Action,
		"risk_level":              assessment.RiskLevel,
		"risk_index":              assessment.RiskIndex,
		"summary":                 assessment.Summary,
		"findings":                assessment.Findings,
		"program_ids":             assessment.ProgramIDs,
		"simulation": map[string]any{
			"ok":             assessment.SimulationOK,
			"error":          assessment.SimulationErr,
			"units_consumed": assessment.UnitsConsumed,
			"logs_count":     len(assessment.Logs),
			"logs":           assessment.Logs,
		},
		"latency_ms": latency.Milliseconds(),
		"warning":    "Shadow mode only: this response does not submit, sign, or block the transaction.",
	}
}

func validateFirewallTransaction(transaction, encoding string) string {
	if transaction == "" {
		return "Serialized transaction is required."
	}
	if encoding != "base64" {
		return "Only base64-encoded serialized transactions are supported."
	}
	decoded, err := base64.StdEncoding.DecodeString(transaction)
	if err != nil {
		return "Transaction is not valid base64."
	}
	if len(decoded) < 64 {
		return "Serialized transaction is too short."
	}
	if len(decoded) > maxFirewallTransactionSize {
		return "Serialized transaction exceeds the firewall size limit."
	}
	return ""
}

func assessTransactionSimulation(simulation services.SolanaSimulationResult) transactionFirewallAssessment {
	logs := sanitizeFirewallLogs(simulation.Value.Logs)
	programIDs := extractFirewallProgramIDs(logs)
	units := int64(0)
	if simulation.Value.UnitsConsumed != nil {
		units = *simulation.Value.UnitsConsumed
	}

	if simulation.Value.Err != nil {
		return transactionFirewallAssessment{
			Action:    "block",
			RiskLevel: "critical",
			RiskIndex: 100,
			Summary:   "Transaction simulation failed. Do not sign until the failure is understood.",
			Findings: []transactionFirewallFinding{{
				Code: "simulation_failed", Severity: "critical", Title: "Simulation failed", Evidence: compactJSON(simulation.Value.Err), Score: 100,
			}},
			ProgramIDs:    programIDs,
			Logs:          logs,
			UnitsConsumed: units,
			SimulationOK:  false,
			SimulationErr: simulation.Value.Err,
		}
	}

	if len(logs) == 0 {
		return transactionFirewallAssessment{
			Action:        "withhold",
			RiskLevel:     "unknown",
			RiskIndex:     0,
			Summary:       "Simulation returned no logs; the firewall withheld a decision.",
			Findings:      []transactionFirewallFinding{},
			ProgramIDs:    programIDs,
			Logs:          logs,
			UnitsConsumed: units,
			SimulationOK:  true,
		}
	}

	findings := detectFirewallFindings(logs, units, len(programIDs))
	score := 0
	for _, finding := range findings {
		score += finding.Score
	}
	if score > 100 {
		score = 100
	}
	action, level := firewallDecision(score)
	summary := "Simulation completed without a high-confidence dangerous instruction signal."
	if len(findings) > 0 {
		summary = "Simulation completed with instruction or execution signals that require review before signing."
	}
	return transactionFirewallAssessment{
		Action:        action,
		RiskLevel:     level,
		RiskIndex:     score,
		Summary:       summary,
		Findings:      findings,
		ProgramIDs:    programIDs,
		Logs:          logs,
		UnitsConsumed: units,
		SimulationOK:  true,
	}
}

func detectFirewallFindings(logs []string, units int64, programCount int) []transactionFirewallFinding {
	type rule struct {
		Needles  []string
		Code     string
		Severity string
		Title    string
		Score    int
	}
	rules := []rule{
		{[]string{"instruction: upgrade", "upgradeableloader", "program upgrade"}, "program_upgrade", "critical", "Upgradeable program mutation", 55},
		{[]string{"instruction: initializepermanentdelegate", "permanent delegate"}, "permanent_delegate", "critical", "Permanent delegate capability", 50},
		{[]string{"instruction: setauthority", "set authority"}, "authority_change", "high", "Authority change", 35},
		{[]string{"instruction: freezeaccount", "freeze account"}, "freeze_account", "high", "Token account freeze", 30},
		{[]string{"instruction: assign", "system instruction: assign"}, "account_owner_change", "high", "Account owner assignment", 30},
		{[]string{"instruction: closeaccount", "close account"}, "close_account", "medium", "Account closure", 20},
		{[]string{"instruction: approvechecked", "instruction: approve", "approve delegate"}, "delegate_approval", "medium", "Delegate approval", 18},
		{[]string{"instruction: burnchecked", "instruction: burn"}, "token_burn", "medium", "Token burn", 15},
		{[]string{"transfer hook", "instruction: executetransferhook"}, "transfer_hook", "medium", "Transfer hook execution", 15},
	}

	findings := make([]transactionFirewallFinding, 0)
	seen := map[string]struct{}{}
	for _, logLine := range logs {
		lower := strings.ToLower(logLine)
		for _, candidate := range rules {
			if _, exists := seen[candidate.Code]; exists {
				continue
			}
			matched := false
			for _, needle := range candidate.Needles {
				if strings.Contains(lower, strings.ToLower(needle)) {
					matched = true
					break
				}
			}
			if matched {
				seen[candidate.Code] = struct{}{}
				findings = append(findings, transactionFirewallFinding{
					Code: candidate.Code, Severity: candidate.Severity, Title: candidate.Title, Evidence: logLine, Score: candidate.Score,
				})
			}
		}
	}

	if units >= 1_200_000 {
		findings = append(findings, transactionFirewallFinding{
			Code: "high_compute_usage", Severity: "medium", Title: "High compute usage", Evidence: "Simulation consumed " + strconv.FormatInt(units, 10) + " compute units.", Score: 15,
		})
	}
	if programCount >= 10 {
		findings = append(findings, transactionFirewallFinding{
			Code: "broad_program_surface", Severity: "medium", Title: "Broad program call surface", Evidence: "Simulation invoked " + strconv.Itoa(programCount) + " distinct programs.", Score: 12,
		})
	}
	return findings
}

func firewallDecision(score int) (string, string) {
	switch {
	case score >= 75:
		return "block", "critical"
	case score >= 50:
		return "warn", "high"
	case score >= 25:
		return "warn", "medium"
	default:
		return "allow", "low"
	}
}

func sanitizeFirewallLogs(input []string) []string {
	if len(input) > maxFirewallLogs {
		input = input[:maxFirewallLogs]
	}
	out := make([]string, 0, len(input))
	for _, line := range input {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 700 {
			line = line[:700]
		}
		out = append(out, line)
	}
	return out
}

func extractFirewallProgramIDs(logs []string) []string {
	seen := map[string]struct{}{}
	for _, line := range logs {
		match := firewallProgramInvokePattern.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		seen[match[1]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for programID := range seen {
		out = append(out, programID)
	}
	sort.Strings(out)
	return out
}

func transactionFirewallEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("KOSCHEI_TRANSACTION_FIREWALL_ENABLED"))
	if raw == "" {
		return true
	}
	enabled, err := strconv.ParseBool(raw)
	return err == nil && enabled
}

func transactionFingerprint(transaction string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(transaction)))
	return "txf_" + hex.EncodeToString(sum[:])[:32]
}

func compactJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "simulation error"
	}
	if len(encoded) > 700 {
		encoded = encoded[:700]
	}
	return string(encoded)
}

func publicFirewallError(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(lower, "429") || strings.Contains(lower, "rate limit"):
		return "Solana RPC capacity is temporarily exhausted."
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline"):
		return "Solana RPC simulation timed out."
	default:
		return "Solana RPC simulation could not be completed."
	}
}

func (h *Handler) saveTransactionFirewallReport(ctx context.Context, requestID, transaction, network, encoding string, assessment transactionFirewallAssessment) {
	if h == nil || h.DB == nil {
		return
	}
	principal, _ := apiPrincipalFromContext(ctx)
	findingsJSON, _ := json.Marshal(assessment.Findings)
	programsJSON, _ := json.Marshal(assessment.ProgramIDs)
	logsJSON, _ := json.Marshal(assessment.Logs)
	errorJSON, _ := json.Marshal(assessment.SimulationErr)
	_, _ = h.DB.ExecContext(ctx, `
		INSERT INTO transaction_firewall_reports (
			request_id,api_key_id,actor_subject,actor_email,transaction_fingerprint,network,encoding,
			action,risk_level,risk_index,simulation_ok,simulation_error,units_consumed,program_ids,findings,logs,shadow_mode
		) VALUES ($1,NULLIF($2,'')::uuid,$3,lower($4),$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14::jsonb,$15::jsonb,$16::jsonb,true)
		ON CONFLICT (request_id) DO NOTHING`,
		requestID, principal.KeyID, principal.AuthSubject, principal.Email, transactionFingerprint(transaction), network, encoding,
		assessment.Action, assessment.RiskLevel, assessment.RiskIndex, assessment.SimulationOK, string(errorJSON), assessment.UnitsConsumed,
		string(programsJSON), string(findingsJSON), string(logsJSON))
}
