package handlers

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/alerts"
	"koschei/api/internal/services"
)

// TransactionGuardV2EvidenceFirst is the production entry point for Guard v2.
// It preserves explicit withhold decisions, alerts on provider outages, verifies
// declared wallet ownership of guarded token accounts and uses stable alert
// identity across client retries. Guard v3 decoding and enrichment are additive
// and do not sign, submit or mutate the serialized transaction.
func (h *Handler) TransactionGuardV2EvidenceFirst(w http.ResponseWriter, r *http.Request) {
	if !transactionFirewallEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "code": "transaction_firewall_disabled", "message": "Transaction Guard is disabled by configuration."})
		return
	}

	var guardRequest transactionGuardV3Request
	if err := decodeJSON(r, &guardRequest); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "invalid_request", "message": "Invalid transaction guard request."})
		return
	}
	input := guardRequest.guardV2Request()
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

	decoded, decodedFindings := decodeTransactionGuardV3(input.Transaction, input.Encoding, input.Wallet)
	fingerprint := transactionFingerprint(input.Transaction)
	signedIntent, signedIntentFindings := evaluateTransactionGuardV3SignedIntent(
		input, guardRequest.SignedIntent, fingerprint, r.Header.Get("Origin"), time.Now().UTC(),
		envBool("TRANSACTION_GUARD_REQUIRE_SIGNED_INTENT", false),
	)
	decoded.SignedIntent = signedIntent
	decodedFindings = uniqueGuardV3Findings(append(decodedFindings, signedIntentFindings...))
	requestID := shieldRequestID(fingerprint, input.Network, time.Now())
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	rpcURL := os.Getenv("SOLANA_RPC_URL")
	if decoded.Available && decoded.AddressLookupCount > 0 {
		resolved, resolutionFindings := resolveTransactionGuardV3AddressLookups(ctx, rpcURL, decoded)
		decoded = resolved
		if decoded.Complete {
			decodedFindings = refreshTransactionGuardV3InstructionFindings(decodedFindings, decoded, resolutionFindings)
		} else {
			decodedFindings = uniqueGuardV3Findings(append(decodedFindings, resolutionFindings...))
		}
	}

	declaredAddresses := make([]string, 0, len(input.Accounts))
	for _, account := range input.Accounts {
		declaredAddresses = append(declaredAddresses, account.Address)
	}
	addresses, automaticBalanceCoverageComplete, automaticBalanceAddressesRequired := transactionGuardV3BalanceAddresses(decoded, input.Wallet, declaredAddresses, guardV3AutomaticAccountLimit)

	var assessment transactionFirewallAssessment
	var cpiFlow transactionGuardCPIFlowAnalysis
	var cpiFindings []transactionFirewallFinding
	var innerGroups []services.SolanaInnerInstructionGroup
	authoritySnapshots := transactionGuardAuthoritySnapshots{}
	intentPolicy := transactionGuardIntentPolicy{Requested: len(input.Accounts) > 0, Complete: len(input.Accounts) == 0, Accounts: []transactionGuardAccountDelta{}}
	stateWitness := unavailableTransactionGuardStateWitness(fingerprint, 0, "No bounded pre-state account set was available for state witnessing.")
	if len(addresses) == 0 {
		simulation, err := services.SolanaSimulateTransaction(ctx, rpcURL, input.Transaction, input.Encoding)
		if err != nil {
			h.finishUnavailableTransactionGuardV3(w, r, input, requestID, started, intentPolicy, decoded, decodedFindings, err)
			return
		}
		stateWitness = unavailableTransactionGuardStateWitness(fingerprint, simulation.Context.Slot, "No bounded pre-state account set was available for state witnessing.")
		assessment = assessTransactionGuardSimulation(simulation)
		innerGroups = simulation.Value.InnerInstructions
		cpiFlow, cpiFindings = resolveTransactionGuardV3CPIFlow(
			ctx, rpcURL, decoded, input.Wallet, input.Accounts, input.ExpectedPrograms, input.RequiredPrograms,
			innerGroups, nil, nil, nil, nil,
		)
	} else {
		pre, ordered, err := services.SolanaGetMultipleAccountsBase64(ctx, rpcURL, addresses)
		if err != nil {
			h.finishUnavailableTransactionGuardV3(w, r, input, requestID, started, intentPolicy, decoded, decodedFindings, err)
			return
		}
		simulation, simulatedOrder, err := services.SolanaSimulateTransactionWithAccountsBase64(ctx, rpcURL, input.Transaction, input.Encoding, ordered)
		if err != nil {
			h.finishUnavailableTransactionGuardV3(w, r, input, requestID, started, intentPolicy, decoded, decodedFindings, err)
			return
		}
		stateWitness = buildTransactionGuardStateWitness(fingerprint, pre.Context.Slot, simulation.Context.Slot, ordered, pre.Value)
		assessment = assessmentFromAccountSimulation(simulation)
		innerGroups = simulation.Value.InnerInstructions
		authoritySnapshots = transactionGuardAuthoritySnapshots{
			PreOrder: ordered, PostOrder: simulatedOrder, Pre: pre.Value, Post: simulation.Value.Accounts,
		}
		if assessment.SimulationOK {
			if len(input.Accounts) > 0 {
				var findings []transactionFirewallFinding
				intentPolicy, findings = evaluateTransactionGuardAccounts(input.Accounts, ordered, simulatedOrder, pre.Value, simulation.Value.Accounts)
				assessment.Findings = append(assessment.Findings, findings...)
				ownerFindings := evaluateTransactionGuardAccountOwners(input.Wallet, input.Accounts, ordered, simulatedOrder, pre.Value, simulation.Value.Accounts, &intentPolicy)
				assessment.Findings = append(assessment.Findings, ownerFindings...)
			}
			automaticBalance, automaticFindings := evaluateTransactionGuardV3AutomaticBalances(
				decoded, input.Wallet, addresses, automaticBalanceAddressesRequired, automaticBalanceCoverageComplete,
				ordered, simulatedOrder, pre.Value, simulation.Value.Accounts,
			)
			decoded.AutomaticBalance = automaticBalance
			decodedFindings = uniqueGuardV3Findings(append(decodedFindings, automaticFindings...))
		}
		cpiFlow, cpiFindings = resolveTransactionGuardV3CPIFlow(
			ctx, rpcURL, decoded, input.Wallet, input.Accounts, input.ExpectedPrograms, input.RequiredPrograms,
			innerGroups, ordered, simulatedOrder, pre.Value, simulation.Value.Accounts,
		)
	}
	decodedFindings = uniqueGuardV3Findings(append(decodedFindings, cpiFindings...))

	authoritySurface, authorityFindings := analyzeTransactionGuardV3AuthoritySurface(decoded, innerGroups, authoritySnapshots)
	decodedFindings = uniqueGuardV3Findings(append(decodedFindings, authorityFindings...))
	decoded = transactionGuardV3DecodedWithAuthoritySurface(decoded, authoritySurface)

	threatDecoded := transactionGuardV3ThreatDecodedWithCPI(decoded, cpiFlow, input.Wallet)
	threatHistory, threatFindings := h.collectTransactionGuardV3ThreatHistory(ctx, input.Network, threatDecoded, input.Wallet)
	decodedFindings = uniqueGuardV3Findings(append(decodedFindings, threatFindings...))
	if threatHistory.Required && !threatHistory.Complete {
		intentPolicy.Complete = false
	}
	if cpiFlow.Required && !cpiFlow.Complete {
		intentPolicy.Complete = false
	}
	if authoritySurface.Required && !authoritySurface.Complete {
		intentPolicy.Complete = false
	}

	assessment.ProgramIDs = normalizeGuardProgramList(append(assessment.ProgramIDs, cpiFlow.ProgramIDs...))
	assessment.ProgramIDs = normalizeGuardProgramList(append(assessment.ProgramIDs, authoritySurface.TransferHookProgramIDs...))
	assessment = applyTransactionGuardV3Decode(assessment, &intentPolicy, decoded, decodedFindings)
	programPolicy, programFindings := evaluateTransactionGuardPrograms(assessment.ProgramIDs, input.ExpectedPrograms, input.RequiredPrograms, input.BlockedPrograms)
	assessment.Findings = append(assessment.Findings, programFindings...)
	assessment = finalizeEvidenceFirstGuardAssessment(assessment, programPolicy, intentPolicy)

	alertID := ""
	if assessment.Action != "allow" {
		alertID = h.emitStableTransactionGuardAlert(r.Context(), requestID, input, assessment, programPolicy, intentPolicy)
	}
	h.finishTransactionGuardV3ResponseWithWitness(w, r, input, requestID, started, assessment, programPolicy, intentPolicy, decoded, threatHistory, cpiFlow, authoritySurface, stateWitness, alertID)
}

func (h *Handler) finishUnavailableTransactionGuardV2(w http.ResponseWriter, r *http.Request, input transactionGuardV2Request, requestID string, started time.Time, intent transactionGuardIntentPolicy, err error) {
	program := transactionGuardProgramPolicy{Complete: false}
	assessment := finalizeEvidenceFirstGuardAssessment(unavailableGuardAssessment(err), program, intent)
	alertID := h.emitStableTransactionGuardAlert(r.Context(), requestID, input, assessment, program, intent)
	h.finishTransactionGuardResponse(w, r, input, requestID, started, assessment, program, intent, alertID)
}

func (h *Handler) finishUnavailableTransactionGuardV3(w http.ResponseWriter, r *http.Request, input transactionGuardV2Request, requestID string, started time.Time, intent transactionGuardIntentPolicy, decoded transactionGuardDecodedTransaction, decodedFindings []transactionFirewallFinding, err error) {
	program := transactionGuardProgramPolicy{Complete: false}
	cpiFlow := unavailableTransactionGuardV3CPIFlow()
	authoritySurface := unavailableTransactionGuardV3AuthoritySurface()
	threatHistory, threatFindings := h.collectTransactionGuardV3ThreatHistory(r.Context(), input.Network, decoded, input.Wallet)
	decodedFindings = uniqueGuardV3Findings(append(decodedFindings, threatFindings...))
	if threatHistory.Required && !threatHistory.Complete {
		intent.Complete = false
	}
	if cpiFlow.Required && !cpiFlow.Complete {
		intent.Complete = false
	}
	if authoritySurface.Required && !authoritySurface.Complete {
		intent.Complete = false
	}
	assessment := applyTransactionGuardV3Decode(unavailableGuardAssessment(err), &intent, decoded, decodedFindings)
	assessment = finalizeEvidenceFirstGuardAssessment(assessment, program, intent)
	alertID := h.emitStableTransactionGuardAlert(r.Context(), requestID, input, assessment, program, intent)
	stateWitness := unavailableTransactionGuardStateWitness(transactionFingerprint(input.Transaction), 0, "Provider failure prevented bounded state witness collection.")
	h.finishTransactionGuardV3ResponseWithWitness(w, r, input, requestID, started, assessment, program, intent, decoded, threatHistory, cpiFlow, authoritySurface, stateWitness, alertID)
}

func finalizeEvidenceFirstGuardAssessment(assessment transactionFirewallAssessment, program transactionGuardProgramPolicy, intent transactionGuardIntentPolicy) transactionFirewallAssessment {
	originalWithhold := assessment.Action == "withhold" || assessment.RiskLevel == "unknown"
	score := 0
	for _, finding := range assessment.Findings {
		score += finding.Score
	}
	if score > 100 {
		score = 100
	}
	assessment.RiskIndex = score
	assessment.Action, assessment.RiskLevel = firewallDecision(score)

	if assessment.Action != "block" && (guardProviderUnavailable(assessment) || originalWithhold || !program.Complete || !intent.Complete) {
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

func evaluateTransactionGuardAccountOwners(wallet string, specs []transactionGuardAccount, preOrder, postOrder []string, pre, post []*services.SolanaAccountInfo, intent *transactionGuardIntentPolicy) []transactionFirewallFinding {
	wallet = strings.TrimSpace(wallet)
	if wallet == "" {
		return nil
	}
	expectedOwner, err := decodeSolanaPublicKey(wallet)
	if err != nil {
		return []transactionFirewallFinding{{Code: "guard_wallet_decode_failed", Severity: "critical", Title: "Declared wallet could not be decoded", Evidence: wallet, Score: 100}}
	}

	preIndex := addressIndex(preOrder)
	postIndex := addressIndex(postOrder)
	findings := []transactionFirewallFinding{}
	for _, spec := range specs {
		mismatch := false
		for _, side := range []struct {
			index map[string]int
			data  []*services.SolanaAccountInfo
		}{
			{index: preIndex, data: pre},
			{index: postIndex, data: post},
		} {
			idx, ok := side.index[spec.Address]
			if !ok || idx >= len(side.data) || side.data[idx] == nil {
				continue
			}
			snapshot, snapshotErr := services.SolanaTokenAccountSnapshotFromInfo(side.data[idx])
			if snapshotErr != nil {
				continue
			}
			if !bytes.Equal(snapshot.Owner[:], expectedOwner) {
				mismatch = true
				break
			}
		}
		if !mismatch {
			continue
		}
		markGuardIntentAccountOwnerMismatch(intent, spec.Address)
		findings = append(findings, transactionFirewallFinding{
			Code: "guard_account_owner_mismatch", Severity: "critical",
			Title:    "Guarded token account owner does not match the declared wallet",
			Evidence: spec.Address + " wallet=" + wallet, Score: 100,
		})
	}
	return findings
}

func markGuardIntentAccountOwnerMismatch(intent *transactionGuardIntentPolicy, address string) {
	if intent == nil {
		return
	}
	for index := range intent.Accounts {
		if intent.Accounts[index].Address == address {
			intent.Accounts[index].PolicyStatus = "fail"
			intent.Accounts[index].EvidenceStatus = "owner_mismatch"
		}
	}
}

func stableTransactionGuardAlertKey(input transactionGuardV2Request, assessment transactionFirewallAssessment) string {
	return "transaction-guard:" + transactionFingerprint(input.Transaction) + ":" + assessment.Action
}

func (h *Handler) emitStableTransactionGuardAlert(ctx context.Context, requestID string, input transactionGuardV2Request, assessment transactionFirewallAssessment, program transactionGuardProgramPolicy, intent transactionGuardIntentPolicy) string {
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
		DedupeKey:   stableTransactionGuardAlertKey(input, assessment),
		EvidenceRef: requestID,
		Payload: map[string]any{
			"request_id": requestID, "transaction_fingerprint": transactionFingerprint(input.Transaction),
			"action": assessment.Action, "risk_index": assessment.RiskIndex,
			"program_policy": program, "intent_policy": intent, "findings": assessment.Findings,
		},
	})
	if err != nil {
		return ""
	}
	return id
}
