package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/alerts"
	"koschei/api/internal/services"
)

const transactionGuardVersion = "v2"

type transactionGuardV2Request struct {
	Transaction      string                    `json:"transaction"`
	Encoding         string                    `json:"encoding"`
	Network          string                    `json:"network"`
	Wallet           string                    `json:"wallet"`
	ExpectedPrograms []string                  `json:"expected_programs"`
	RequiredPrograms []string                  `json:"required_programs"`
	BlockedPrograms  []string                  `json:"blocked_programs"`
	Accounts         []transactionGuardAccount `json:"accounts"`
}

type transactionGuardAccount struct {
	Address           string `json:"address"`
	Mint              string `json:"mint,omitempty"`
	Role              string `json:"role"`
	Decimals          *int   `json:"decimals,omitempty"`
	MaximumSpendRaw   string `json:"maximum_spend_raw,omitempty"`
	MinimumReceiveRaw string `json:"minimum_receive_raw,omitempty"`
	QuotedReceiveRaw  string `json:"quoted_receive_raw,omitempty"`
	MaxSlippageBPS    int    `json:"max_slippage_bps,omitempty"`
}

type transactionGuardAccountDelta struct {
	Address           string `json:"address"`
	Mint              string `json:"mint,omitempty"`
	MintVerified      bool   `json:"-"`
	Role              string `json:"role"`
	Decimals          *int   `json:"decimals,omitempty"`
	PreAmountRaw      string `json:"pre_amount_raw"`
	PostAmountRaw     string `json:"post_amount_raw"`
	DeltaRaw          string `json:"delta_raw"`
	SpentRaw          string `json:"spent_raw,omitempty"`
	ReceivedRaw       string `json:"received_raw,omitempty"`
	MaximumSpendRaw   string `json:"maximum_spend_raw,omitempty"`
	MinimumReceiveRaw string `json:"minimum_receive_raw,omitempty"`
	QuotedReceiveRaw  string `json:"quoted_receive_raw,omitempty"`
	SlippageBPS       *int64 `json:"slippage_bps,omitempty"`
	MaxSlippageBPS    int    `json:"max_slippage_bps,omitempty"`
	PolicyStatus      string `json:"policy_status"`
	EvidenceStatus    string `json:"evidence_status"`
}

type transactionGuardProgramPolicy struct {
	Invoked         []string `json:"invoked"`
	Expected        []string `json:"expected"`
	Required        []string `json:"required"`
	Blocked         []string `json:"blocked"`
	Unexpected      []string `json:"unexpected"`
	MissingRequired []string `json:"missing_required"`
	BlockedInvoked  []string `json:"blocked_invoked"`
	Complete        bool     `json:"complete"`
}

type transactionGuardIntentPolicy struct {
	Requested bool                           `json:"requested"`
	Complete  bool                           `json:"complete"`
	Accounts  []transactionGuardAccountDelta `json:"accounts"`
}

func (h *Handler) TransactionGuardV2(w http.ResponseWriter, r *http.Request) {
	if !transactionFirewallEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "code": "transaction_firewall_disabled", "message": "Transaction Guard is disabled by configuration."})
		return
	}

	var input transactionGuardV2Request
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "invalid_request", "message": "Invalid transaction guard request."})
		return
	}
	input.Transaction = strings.TrimSpace(input.Transaction)
	input.Encoding = strings.ToLower(strings.TrimSpace(input.Encoding))
	if input.Encoding == "" {
		input.Encoding = "base64"
	}
	if err := validateFirewallTransaction(input.Transaction, input.Encoding); err != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "invalid_transaction", "message": err})
		return
	}
	input.Network = strings.TrimSpace(input.Network)
	if input.Network == "" {
		input.Network = "solana-mainnet"
	}
	if input.Network != "solana-mainnet" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "unsupported_network", "message": "Transaction Guard currently supports solana-mainnet only."})
		return
	}
	if err := validateTransactionGuardInput(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "invalid_guard_policy", "message": err.Error()})
		return
	}

	requestID := shieldRequestID(transactionFingerprint(input.Transaction), input.Network, time.Now())
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	addresses := make([]string, 0, len(input.Accounts))
	for _, account := range input.Accounts {
		addresses = append(addresses, account.Address)
	}

	var assessment transactionFirewallAssessment
	intentPolicy := transactionGuardIntentPolicy{Requested: len(input.Accounts) > 0, Complete: len(input.Accounts) == 0, Accounts: []transactionGuardAccountDelta{}}
	if len(addresses) == 0 {
		simulation, err := services.SolanaSimulateTransaction(ctx, os.Getenv("SOLANA_RPC_URL"), input.Transaction, input.Encoding)
		if err != nil {
			assessment = unavailableGuardAssessment(err)
			h.finishTransactionGuardResponse(w, r, input, requestID, started, assessment, transactionGuardProgramPolicy{Complete: false}, intentPolicy, "")
			return
		}
		assessment = assessTransactionGuardSimulation(simulation)
	} else {
		pre, ordered, err := services.SolanaGetMultipleAccountsBase64(ctx, os.Getenv("SOLANA_RPC_URL"), addresses)
		if err != nil {
			assessment = unavailableGuardAssessment(err)
			h.finishTransactionGuardResponse(w, r, input, requestID, started, assessment, transactionGuardProgramPolicy{Complete: false}, intentPolicy, "")
			return
		}
		simulation, simulatedOrder, err := services.SolanaSimulateTransactionWithAccountsBase64(ctx, os.Getenv("SOLANA_RPC_URL"), input.Transaction, input.Encoding, ordered)
		if err != nil {
			assessment = unavailableGuardAssessment(err)
			h.finishTransactionGuardResponse(w, r, input, requestID, started, assessment, transactionGuardProgramPolicy{Complete: false}, intentPolicy, "")
			return
		}
		assessment = assessmentFromAccountSimulation(simulation)
		if assessment.SimulationOK {
			var findings []transactionFirewallFinding
			intentPolicy, findings = evaluateTransactionGuardAccounts(input.Accounts, ordered, simulatedOrder, pre.Value, simulation.Value.Accounts)
			assessment.Findings = append(assessment.Findings, findings...)
		}
	}

	programPolicy, programFindings := evaluateTransactionGuardPrograms(assessment.ProgramIDs, input.ExpectedPrograms, input.RequiredPrograms, input.BlockedPrograms)
	assessment.Findings = append(assessment.Findings, programFindings...)
	assessment = finalizeGuardAssessment(assessment, programPolicy, intentPolicy)

	alertID := ""
	if assessment.Action != "allow" {
		alertID = h.emitTransactionGuardAlert(r.Context(), requestID, input, assessment, programPolicy, intentPolicy)
	}
	h.finishTransactionGuardResponse(w, r, input, requestID, started, assessment, programPolicy, intentPolicy, alertID)
}

func validateTransactionGuardInput(input *transactionGuardV2Request) error {
	if input == nil {
		return fmt.Errorf("guard request is required")
	}
	if len(input.ExpectedPrograms) > 64 || len(input.RequiredPrograms) > 64 || len(input.BlockedPrograms) > 64 {
		return fmt.Errorf("program policy exceeds the 64-program limit")
	}
	if len(input.Accounts) > 32 {
		return fmt.Errorf("account policy exceeds the 32-account limit")
	}
	seen := map[string]bool{}
	for i := range input.Accounts {
		account := &input.Accounts[i]
		account.Address = strings.TrimSpace(account.Address)
		account.Mint = strings.TrimSpace(account.Mint)
		account.Role = strings.ToLower(strings.TrimSpace(account.Role))
		if !looksLikeGuardPubkey(account.Address) {
			return fmt.Errorf("account %d has an invalid Solana address", i)
		}
		if seen[account.Address] {
			return fmt.Errorf("duplicate guarded account: %s", account.Address)
		}
		seen[account.Address] = true
		switch account.Role {
		case "input", "output", "observe":
		default:
			return fmt.Errorf("account %d role must be input, output or observe", i)
		}
		if account.Decimals != nil && (*account.Decimals < 0 || *account.Decimals > 18) {
			return fmt.Errorf("account %d decimals must be between 0 and 18", i)
		}
		if _, err := optionalRawAmount(account.MaximumSpendRaw); err != nil {
			return fmt.Errorf("account %d maximum_spend_raw is invalid", i)
		}
		if _, err := optionalRawAmount(account.MinimumReceiveRaw); err != nil {
			return fmt.Errorf("account %d minimum_receive_raw is invalid", i)
		}
		if _, err := optionalRawAmount(account.QuotedReceiveRaw); err != nil {
			return fmt.Errorf("account %d quoted_receive_raw is invalid", i)
		}
		if account.MaxSlippageBPS < 0 || account.MaxSlippageBPS > 10_000 {
			return fmt.Errorf("account %d max_slippage_bps must be between 0 and 10000", i)
		}
	}
	input.ExpectedPrograms = normalizeGuardProgramList(input.ExpectedPrograms)
	input.RequiredPrograms = normalizeGuardProgramList(input.RequiredPrograms)
	input.BlockedPrograms = normalizeGuardProgramList(input.BlockedPrograms)
	return nil
}

func assessTransactionGuardSimulation(simulation services.SolanaSimulationResult) transactionFirewallAssessment {
	assessment := assessTransactionSimulation(simulation)
	// Program policy is security-sensitive and must inspect the complete RPC log
	// surface. Only the response copy is capped by sanitizeFirewallLogs.
	assessment.ProgramIDs = extractFirewallProgramIDs(simulation.Value.Logs)
	return assessment
}

func assessmentFromAccountSimulation(simulation services.SolanaSimulationAccountsResult) transactionFirewallAssessment {
	var base services.SolanaSimulationResult
	base.Context.Slot = simulation.Context.Slot
	base.Value.Err = simulation.Value.Err
	base.Value.Logs = simulation.Value.Logs
	base.Value.Accounts = simulation.Value.Accounts
	base.Value.UnitsConsumed = simulation.Value.UnitsConsumed
	base.Value.ReturnData = simulation.Value.ReturnData
	base.Value.InnerInstructions = simulation.Value.InnerInstructions
	base.Value.ReplacementBlockhash = simulation.Value.ReplacementBlockhash
	return assessTransactionGuardSimulation(base)
}

func unavailableGuardAssessment(err error) transactionFirewallAssessment {
	return transactionFirewallAssessment{
		Action: "withhold", RiskLevel: "unknown", RiskIndex: 0,
		Summary:  "Simulation provider is unavailable; Transaction Guard withheld a decision.",
		Findings: []transactionFirewallFinding{}, ProgramIDs: []string{}, Logs: []string{}, SimulationOK: false,
		SimulationErr: map[string]any{"code": "rpc_unavailable", "message": publicFirewallError(err.Error())},
	}
}

func evaluateTransactionGuardPrograms(invoked, expected, required, blocked []string) (transactionGuardProgramPolicy, []transactionFirewallFinding) {
	invoked = normalizeGuardProgramList(invoked)
	expected = normalizeGuardProgramList(expected)
	required = normalizeGuardProgramList(required)
	blocked = normalizeGuardProgramList(append(blocked, splitGuardPrograms(os.Getenv("TRANSACTION_GUARD_BLOCKED_PROGRAMS"))...))
	baseAllowed := guardBuiltinPrograms()
	allowed := stringSet(append(append([]string{}, baseAllowed...), expected...))
	invokedSet := stringSet(invoked)
	blockedSet := stringSet(blocked)

	policy := transactionGuardProgramPolicy{Invoked: invoked, Expected: expected, Required: required, Blocked: blocked, Unexpected: []string{}, MissingRequired: []string{}, BlockedInvoked: []string{}, Complete: true}
	findings := []transactionFirewallFinding{}
	for _, program := range invoked {
		if blockedSet[program] {
			policy.BlockedInvoked = append(policy.BlockedInvoked, program)
		}
		if len(expected) > 0 && !allowed[program] {
			policy.Unexpected = append(policy.Unexpected, program)
		}
	}
	for _, program := range required {
		if !invokedSet[program] {
			policy.MissingRequired = append(policy.MissingRequired, program)
		}
	}
	if len(policy.BlockedInvoked) > 0 {
		findings = append(findings, transactionFirewallFinding{Code: "blocked_program_invoked", Severity: "critical", Title: "Blocked program invoked", Evidence: strings.Join(policy.BlockedInvoked, ", "), Score: 100})
	}
	if len(policy.Unexpected) > 0 {
		findings = append(findings, transactionFirewallFinding{Code: "unexpected_program", Severity: "high", Title: "Unexpected program in transaction route", Evidence: strings.Join(policy.Unexpected, ", "), Score: 45})
	}
	if len(policy.MissingRequired) > 0 {
		findings = append(findings, transactionFirewallFinding{Code: "required_program_missing", Severity: "high", Title: "Required route program was not invoked", Evidence: strings.Join(policy.MissingRequired, ", "), Score: 35})
	}
	policy.Complete = len(policy.BlockedInvoked) == 0 && len(policy.Unexpected) == 0 && len(policy.MissingRequired) == 0
	return policy, findings
}

func evaluateTransactionGuardAccounts(specs []transactionGuardAccount, preOrder, postOrder []string, pre, post []*services.SolanaAccountInfo) (transactionGuardIntentPolicy, []transactionFirewallFinding) {
	policy := transactionGuardIntentPolicy{Requested: len(specs) > 0, Complete: true, Accounts: []transactionGuardAccountDelta{}}
	findings := []transactionFirewallFinding{}
	preIndex := addressIndex(preOrder)
	postIndex := addressIndex(postOrder)
	for _, spec := range specs {
		result := transactionGuardAccountDelta{Address: spec.Address, Mint: spec.Mint, Role: spec.Role, Decimals: spec.Decimals, MaximumSpendRaw: spec.MaximumSpendRaw, MinimumReceiveRaw: spec.MinimumReceiveRaw, QuotedReceiveRaw: spec.QuotedReceiveRaw, MaxSlippageBPS: spec.MaxSlippageBPS, PolicyStatus: "pass", EvidenceStatus: "verified_rpc_simulation"}
		pi, pok := preIndex[spec.Address]
		qi, qok := postIndex[spec.Address]
		if !pok || !qok || pi >= len(pre) || qi >= len(post) {
			appendGuardAccountWithhold(&policy, &findings, result, "account_missing", "guard_account_missing", "Guarded account evidence is unavailable")
			continue
		}

		preSnapshot, prePresent, preErr := guardTokenAccountSide(pre[pi], spec.Role == "output")
		postSnapshot, postPresent, postErr := guardTokenAccountSide(post[qi], spec.Role == "input")
		if preErr != nil || postErr != nil || (!prePresent && !postPresent) {
			appendGuardAccountWithhold(&policy, &findings, result, "account_decode_failed", "guard_account_decode_failed", "Guarded token account could not be decoded")
			continue
		}
		if prePresent && postPresent && !bytes.Equal(preSnapshot.Mint[:], postSnapshot.Mint[:]) {
			result.PolicyStatus = "fail"
			result.EvidenceStatus = "account_mint_changed"
			policy.Accounts = append(policy.Accounts, result)
			findings = append(findings, transactionFirewallFinding{Code: "guard_account_mint_changed", Severity: "critical", Title: "Guarded token account mint changed", Evidence: spec.Address, Score: 100})
			continue
		}

		if spec.Mint != "" {
			expectedMint, err := decodeSolanaPublicKey(spec.Mint)
			if err != nil || (prePresent && !bytes.Equal(preSnapshot.Mint[:], expectedMint)) || (postPresent && !bytes.Equal(postSnapshot.Mint[:], expectedMint)) {
				result.PolicyStatus = "fail"
				result.EvidenceStatus = "mint_mismatch"
				policy.Accounts = append(policy.Accounts, result)
				findings = append(findings, transactionFirewallFinding{Code: "guard_account_mint_mismatch", Severity: "critical", Title: "Guarded token account mint does not match the declared asset", Evidence: spec.Address, Score: 100})
				continue
			}
			result.MintVerified = true
		}

		preAmount := uint64(0)
		postAmount := uint64(0)
		if prePresent {
			preAmount = preSnapshot.Amount
		}
		if postPresent {
			postAmount = postSnapshot.Amount
		}
		if !prePresent {
			result.EvidenceStatus = "verified_rpc_simulation_created_account"
		}
		if !postPresent {
			result.EvidenceStatus = "verified_rpc_simulation_closed_account"
		}

		preBig := new(big.Int).SetUint64(preAmount)
		postBig := new(big.Int).SetUint64(postAmount)
		delta := new(big.Int).Sub(new(big.Int).Set(postBig), preBig)
		spent := big.NewInt(0)
		received := big.NewInt(0)
		if delta.Sign() < 0 {
			spent.Neg(delta)
		} else {
			received.Set(delta)
		}
		result.PreAmountRaw = preBig.String()
		result.PostAmountRaw = postBig.String()
		result.DeltaRaw = delta.String()
		result.SpentRaw = spent.String()
		result.ReceivedRaw = received.String()

		if maxSpend, _ := optionalRawAmount(spec.MaximumSpendRaw); maxSpend != nil && spent.Cmp(maxSpend) > 0 {
			result.PolicyStatus = "fail"
			findings = append(findings, transactionFirewallFinding{Code: "maximum_spend_exceeded", Severity: "critical", Title: "Maximum token spend exceeded", Evidence: fmt.Sprintf("%s spent=%s max=%s", spec.Address, spent.String(), maxSpend.String()), Score: 80})
		}
		if minReceive, _ := optionalRawAmount(spec.MinimumReceiveRaw); minReceive != nil && received.Cmp(minReceive) < 0 {
			result.PolicyStatus = "fail"
			findings = append(findings, transactionFirewallFinding{Code: "minimum_receive_not_met", Severity: "critical", Title: "Minimum token receive amount was not met", Evidence: fmt.Sprintf("%s received=%s minimum=%s", spec.Address, received.String(), minReceive.String()), Score: 80})
		}
		if quote, _ := optionalRawAmount(spec.QuotedReceiveRaw); quote != nil && quote.Sign() > 0 {
			slippage := int64(0)
			if received.Cmp(quote) < 0 {
				loss := new(big.Int).Sub(new(big.Int).Set(quote), received)
				bps := new(big.Int).Div(new(big.Int).Mul(loss, big.NewInt(10_000)), quote)
				if bps.IsInt64() {
					slippage = bps.Int64()
				} else {
					slippage = 10_000
				}
			}
			result.SlippageBPS = &slippage
			if spec.MaxSlippageBPS > 0 && slippage > int64(spec.MaxSlippageBPS) {
				result.PolicyStatus = "fail"
				findings = append(findings, transactionFirewallFinding{Code: "slippage_limit_exceeded", Severity: "high", Title: "Swap slippage exceeds the declared limit", Evidence: fmt.Sprintf("%s slippage_bps=%d max_bps=%d", spec.Address, slippage, spec.MaxSlippageBPS), Score: 50})
			}
		}
		policy.Accounts = append(policy.Accounts, result)
	}
	return policy, findings
}

func guardTokenAccountSide(info *services.SolanaAccountInfo, allowMissing bool) (services.SolanaTokenAccountSnapshot, bool, error) {
	if info == nil {
		if allowMissing {
			return services.SolanaTokenAccountSnapshot{}, false, nil
		}
		return services.SolanaTokenAccountSnapshot{}, false, fmt.Errorf("token account side is unavailable")
	}
	snapshot, err := services.SolanaTokenAccountSnapshotFromInfo(info)
	return snapshot, true, err
}

func appendGuardAccountWithhold(policy *transactionGuardIntentPolicy, findings *[]transactionFirewallFinding, result transactionGuardAccountDelta, evidenceStatus, code, title string) {
	result.PolicyStatus = "withhold"
	result.EvidenceStatus = evidenceStatus
	policy.Complete = false
	policy.Accounts = append(policy.Accounts, result)
	*findings = append(*findings, transactionFirewallFinding{Code: code, Severity: "high", Title: title, Evidence: result.Address, Score: 30})
}

func finalizeGuardAssessment(assessment transactionFirewallAssessment, program transactionGuardProgramPolicy, intent transactionGuardIntentPolicy) transactionFirewallAssessment {
	score := 0
	for _, finding := range assessment.Findings {
		score += finding.Score
	}
	if score > 100 {
		score = 100
	}
	assessment.RiskIndex = score
	assessment.Action, assessment.RiskLevel = firewallDecision(score)
	if guardProviderUnavailable(assessment) {
		assessment.Action = "withhold"
		assessment.RiskLevel = "unknown"
	}
	if (!program.Complete || !intent.Complete) && assessment.Action == "allow" {
		assessment.Action = "withhold"
		assessment.RiskLevel = "unknown"
	}
	switch assessment.Action {
	case "block":
		assessment.Summary = "Transaction Guard detected a policy violation or dangerous execution signal. Do not sign."
	case "warn":
		assessment.Summary = "Transaction Guard detected execution evidence that requires review before signing."
	case "withhold":
		assessment.Summary = "Transaction Guard could not complete every required evidence check and withheld a safe decision."
	default:
		assessment.Summary = "Transaction Guard verified the declared program and token-account policies without a blocking finding."
	}
	return assessment
}

func guardProviderUnavailable(assessment transactionFirewallAssessment) bool {
	value, ok := assessment.SimulationErr.(map[string]any)
	if !ok {
		return false
	}
	code, _ := value["code"].(string)
	return strings.EqualFold(strings.TrimSpace(code), "rpc_unavailable")
}

func guardHTTPStatus(assessment transactionFirewallAssessment) int {
	if guardProviderUnavailable(assessment) {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

func (h *Handler) finishTransactionGuardResponse(w http.ResponseWriter, r *http.Request, input transactionGuardV2Request, requestID string, started time.Time, assessment transactionFirewallAssessment, programPolicy transactionGuardProgramPolicy, intentPolicy transactionGuardIntentPolicy, alertID string) {
	guardComplete := assessment.SimulationOK && programPolicy.Complete && intentPolicy.Complete
	originalAction := assessment.Action
	assessment, enforcement := applyTransactionGuardEnforcementRequirement(input, requestID, assessment, guardComplete, time.Now().UTC())
	if originalAction == "allow" && assessment.Action != "allow" && alertID == "" {
		alertID = h.emitTransactionGuardAlert(r.Context(), requestID, input, assessment, programPolicy, intentPolicy)
	}
	h.saveTransactionGuardV2Report(r.Context(), requestID, input, assessment, programPolicy, intentPolicy, guardComplete, alertID)
	response := map[string]any{
		"ok":                      !guardProviderUnavailable(assessment),
		"request_id":              requestID,
		"product":                 "Koschei Transaction Guard",
		"guard_version":           transactionGuardVersion,
		"mode":                    transactionFirewallMode,
		"shadow_mode":             true,
		"enforcement_enabled":     enforcement.Configured,
		"billable":                false,
		"network":                 input.Network,
		"encoding":                input.Encoding,
		"wallet":                  strings.TrimSpace(input.Wallet),
		"transaction_fingerprint": transactionFingerprint(input.Transaction),
		"action":                  assessment.Action,
		"risk_level":              assessment.RiskLevel,
		"risk_index":              assessment.RiskIndex,
		"summary":                 assessment.Summary,
		"findings":                assessment.Findings,
		"guard_complete":          guardComplete,
		"program_policy":          programPolicy,
		"intent_policy":           intentPolicy,
		"alert_event_id":          alertID,
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

func (h *Handler) emitTransactionGuardAlert(ctx context.Context, requestID string, input transactionGuardV2Request, assessment transactionFirewallAssessment, program transactionGuardProgramPolicy, intent transactionGuardIntentPolicy) string {
	if h == nil || h.DB == nil {
		return ""
	}
	principal, _ := apiPrincipalFromContext(ctx)
	severity := assessment.RiskLevel
	if severity == "unknown" {
		severity = "medium"
	}
	id, err := alerts.Emit(ctx, h.DB, alerts.Event{
		AuthSubject: principal.AuthSubject,
		Source:      "transaction_guard",
		EventType:   alerts.EventTransactionGuardDecision,
		Severity:    severity,
		Target:      firstNonEmptyString(strings.TrimSpace(input.Wallet), transactionFingerprint(input.Transaction)),
		Title:       "Transaction Guard: " + strings.ToUpper(assessment.Action),
		Message:     assessment.Summary,
		DedupeKey:   "transaction-guard:" + requestID,
		EvidenceRef: requestID,
		Payload: map[string]any{
			"request_id": requestID, "action": assessment.Action, "risk_index": assessment.RiskIndex,
			"program_policy": program, "intent_policy": intent, "findings": assessment.Findings,
		},
	})
	if err != nil {
		return ""
	}
	return id
}

func (h *Handler) saveTransactionGuardV2Report(ctx context.Context, requestID string, input transactionGuardV2Request, assessment transactionFirewallAssessment, program transactionGuardProgramPolicy, intent transactionGuardIntentPolicy, guardComplete bool, alertID string) {
	if h == nil || h.DB == nil {
		return
	}
	principal, _ := apiPrincipalFromContext(ctx)
	findingsJSON, _ := json.Marshal(assessment.Findings)
	programsJSON, _ := json.Marshal(assessment.ProgramIDs)
	logsJSON, _ := json.Marshal(assessment.Logs)
	errorJSON, _ := json.Marshal(assessment.SimulationErr)
	accountJSON, _ := json.Marshal(intent.Accounts)
	programPolicyJSON, _ := json.Marshal(program)
	intentPolicyJSON, _ := json.Marshal(intent)
	_, _ = h.DB.ExecContext(ctx, `
		INSERT INTO transaction_firewall_reports (
			request_id,api_key_id,actor_subject,actor_email,transaction_fingerprint,network,encoding,
			action,risk_level,risk_index,simulation_ok,simulation_error,units_consumed,program_ids,findings,logs,shadow_mode,
			guard_version,guard_complete,account_deltas,program_policy,intent_policy,alert_event_id
		) VALUES ($1,NULLIF($2,'')::uuid,$3,lower($4),$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14::jsonb,$15::jsonb,$16::jsonb,true,
		          $17,$18,$19::jsonb,$20::jsonb,$21::jsonb,NULLIF($22,'')::uuid)
		ON CONFLICT (request_id) DO NOTHING`,
		requestID, principal.KeyID, principal.AuthSubject, principal.Email, transactionFingerprint(input.Transaction), input.Network, input.Encoding,
		assessment.Action, assessment.RiskLevel, assessment.RiskIndex, assessment.SimulationOK, string(errorJSON), assessment.UnitsConsumed,
		string(programsJSON), string(findingsJSON), string(logsJSON), transactionGuardVersion, guardComplete, string(accountJSON), string(programPolicyJSON), string(intentPolicyJSON), alertID)
}

func optionalRawAmount(raw string) (*big.Int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	value, ok := new(big.Int).SetString(raw, 10)
	if !ok || value.Sign() < 0 {
		return nil, fmt.Errorf("raw amount must be a non-negative base-10 integer")
	}
	return value, nil
}

func addressIndex(addresses []string) map[string]int {
	out := map[string]int{}
	for index, address := range addresses {
		out[strings.TrimSpace(address)] = index
	}
	return out
}

func normalizeGuardProgramList(input []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range input {
		value = strings.TrimSpace(value)
		if !looksLikeGuardPubkey(value) || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func splitGuardPrograms(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func stringSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func looksLikeGuardPubkey(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 32 || len(value) > 44 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", char) {
			return false
		}
	}
	return true
}

func guardBuiltinPrograms() []string {
	return []string{
		"11111111111111111111111111111111",
		"ComputeBudget111111111111111111111111111111",
		"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
		"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
		"ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
		"MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
	}
}

func guardSlippagePercent(bps *int64) string {
	if bps == nil {
		return ""
	}
	return strconv.FormatFloat(float64(*bps)/100, 'f', 2, 64) + "%"
}
