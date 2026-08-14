package services

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type arvisTransactionEvidence struct {
	Available             bool
	Signature             string
	Slot                  int64
	BlockTime             int64
	FeeLamports           int64
	ComputeUnits          int64
	InnerInstructionCount int
	AccountKeys           []string
	Signers               []string
	WritableCount         int
	ProgramIDs            []string
	InstructionTypes      []string
	TokenMints            []string
	TokenBalanceChanges   map[string]float64
	LamportDeltas         map[string]int64
	FundingAccounts       []string
	CreatorCandidate      string
	InitializeMint        bool
	CreateAccount         bool
	RaydiumRelated        bool
	PumpRelated           bool
	ComputeBudgetRelated  bool
	JitoRelated           bool
	Errors                []string
}

func AnalyzeArvisRadarsWithTransactions(req SecurityRadarRequest) ArvisAnalysis {
	analysis := AnalyzeArvisRadars(req)
	txEvidence := collectArvisTransactionEvidence(req, analysis.Arms)
	if !txEvidence.Available {
		analysis.Bundle.Metadata["transaction_evidence_available"] = false
		analysis.Bundle.Metadata["transaction_evidence_errors"] = txEvidence.Errors
		return analysis
	}

	generatedAt := time.Now().UTC().Format(time.RFC3339)
	arms := append([]SecurityRadarVerdict(nil), analysis.Arms...)
	replaceArvisArm(arms, buildTransactionMEVArm(req, txEvidence, generatedAt))
	replaceArvisArm(arms, buildLiquidityMovementTransactionArm(req, txEvidence, generatedAt))
	replaceArvisArm(arms, buildCreatorLinkTransactionArm(req, txEvidence, generatedAt))
	replaceFundingClusterArmPreservingHolderEvidence(arms, buildFundingClusterTransactionArm(req, txEvidence, generatedAt))
	replaceArvisArm(arms, buildTransactionIntentProgramArm(req, txEvidence, generatedAt))

	withoutFinal := make([]SecurityRadarVerdict, 0, len(arms)-1)
	for _, arm := range arms {
		if arm.ModuleID != ModuleFinalVerdictEngine {
			withoutFinal = append(withoutFinal, arm)
		}
	}
	finalArm := buildFinalArm(req, withoutFinal, generatedAt)
	replaceArvisArm(arms, finalArm)
	final := finalVerdictFromArm(finalArm)
	verified := verifiedArvisArmCount(arms)

	analysis.Arms = arms
	analysis.Final = final
	analysis.Bundle.Metadata["arvis_arms"] = arms
	analysis.Bundle.Metadata["verified_arm_count"] = verified
	analysis.Bundle.Metadata["runtime_arm_count"] = verified
	analysis.Bundle.Metadata["transaction_evidence_available"] = true
	analysis.Bundle.Metadata["transaction_signature"] = txEvidence.Signature
	analysis.Bundle.Metadata["transaction_program_count"] = len(txEvidence.ProgramIDs)
	analysis.Bundle.Metadata["transaction_signer_count"] = len(txEvidence.Signers)
	analysis.Bundle.Metadata["final_grade"] = final.Grade
	analysis.Bundle.Metadata["final_risk_index"] = final.RiskIndex
	analysis.Bundle.Metadata["final_risk_level"] = final.RiskLevel
	analysis.Bundle.Metadata["final_recommendation"] = final.Recommendation
	analysis.Bundle.CustomerRecommendation = final.Recommendation
	if final.Signed {
		analysis.Bundle.CustomerSummary = fmt.Sprintf("ARVIS verified %d of 13 evidence arms, including parsed transaction evidence, and produced one signed verdict.", verified)
	}
	return analysis
}

func collectArvisTransactionEvidence(req SecurityRadarRequest, arms []SecurityRadarVerdict) arvisTransactionEvidence {
	out := arvisTransactionEvidence{TokenBalanceChanges: map[string]float64{}, LamportDeltas: map[string]int64{}}
	rpcURL := strings.TrimSpace(os.Getenv("SOLANA_RPC_URL"))
	if rpcURL == "" {
		out.Errors = append(out.Errors, "SOLANA_RPC_URL is unavailable")
		return out
	}

	signature := ""
	if looksLikeSolanaSignature(req.Target) {
		signature = strings.TrimSpace(req.Target)
	}
	if signature == "" {
		for _, arm := range arms {
			if arm.Signals == nil {
				continue
			}
			if value := strings.TrimSpace(anyString(arm.Signals["latest_signature"])); value != "" {
				signature = value
				break
			}
		}
	}
	if signature == "" && isLikelyRadarSolanaAddress(strings.TrimSpace(req.Target)) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		signatures, err := SolanaGetSignaturesForAddress(ctx, rpcURL, req.Target, 1)
		cancel()
		if err == nil && len(signatures) > 0 {
			signature = strings.TrimSpace(signatures[0].Signature)
		} else if err != nil {
			out.Errors = append(out.Errors, compactRadarError("getSignaturesForAddress", err))
		}
	}
	if signature == "" {
		out.Errors = append(out.Errors, "no transaction signature available for enrichment")
		return out
	}

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	tx, err := SolanaGetTransactionJSONParsed(ctx, rpcURL, signature)
	cancel()
	if err != nil {
		out.Errors = append(out.Errors, compactRadarError("getTransaction", err))
		return out
	}
	out.Signature = signature
	parseArvisTransactionMap(map[string]any(tx), &out)
	out.Available = len(out.AccountKeys) > 0 || len(out.ProgramIDs) > 0
	if !out.Available {
		out.Errors = append(out.Errors, "transaction response did not contain parsed account or program evidence")
	}
	return out
}

func parseArvisTransactionMap(tx map[string]any, out *arvisTransactionEvidence) {
	if out == nil {
		return
	}
	out.Slot = radarInt64(tx["slot"])
	out.BlockTime = radarInt64(tx["blockTime"])
	transaction := asRadarMap(tx["transaction"])
	message := asRadarMap(transaction["message"])
	meta := asRadarMap(tx["meta"])
	out.FeeLamports = radarInt64(meta["fee"])
	out.ComputeUnits = radarInt64(meta["computeUnitsConsumed"])

	keysRaw, _ := message["accountKeys"].([]any)
	for _, raw := range keysRaw {
		pubkey := ""
		signer := false
		writable := false
		switch value := raw.(type) {
		case string:
			pubkey = strings.TrimSpace(value)
		case map[string]any:
			pubkey = strings.TrimSpace(anyString(value["pubkey"]))
			signer, _ = value["signer"].(bool)
			writable, _ = value["writable"].(bool)
		}
		if pubkey == "" {
			continue
		}
		out.AccountKeys = append(out.AccountKeys, pubkey)
		if signer {
			out.Signers = append(out.Signers, pubkey)
		}
		if writable {
			out.WritableCount++
		}
	}

	programSet := map[string]bool{}
	typeSet := map[string]bool{}
	mintSet := map[string]bool{}
	parseInstructionList(message["instructions"], out, programSet, typeSet, mintSet)
	if inner, ok := meta["innerInstructions"].([]any); ok {
		for _, raw := range inner {
			item := asRadarMap(raw)
			if instructions, ok := item["instructions"].([]any); ok {
				out.InnerInstructionCount += len(instructions)
			}
			parseInstructionList(item["instructions"], out, programSet, typeSet, mintSet)
		}
	}

	for program := range programSet {
		out.ProgramIDs = append(out.ProgramIDs, program)
	}
	for instructionType := range typeSet {
		out.InstructionTypes = append(out.InstructionTypes, instructionType)
	}
	for mint := range mintSet {
		out.TokenMints = append(out.TokenMints, mint)
	}
	sort.Strings(out.ProgramIDs)
	sort.Strings(out.InstructionTypes)
	sort.Strings(out.TokenMints)

	applyLamportDeltas(meta, out)
	applyTokenBalanceDeltas(meta, out, mintSet)
	for mint := range mintSet {
		if !containsString(out.TokenMints, mint) {
			out.TokenMints = append(out.TokenMints, mint)
		}
	}
	sort.Strings(out.TokenMints)

	logs := radarStringSlice(meta["logMessages"])
	logText := strings.ToLower(strings.Join(logs, "\n"))
	for _, program := range out.ProgramIDs {
		if isKnownRaydiumProgram(program) {
			out.RaydiumRelated = true
		}
		if program == "ComputeBudget111111111111111111111111111111" {
			out.ComputeBudgetRelated = true
		}
		if pumpProgram := strings.TrimSpace(os.Getenv("PUMP_FUN_PROGRAM_ID")); pumpProgram != "" && program == pumpProgram {
			out.PumpRelated = true
		}
	}
	if strings.Contains(logText, "raydium") || strings.Contains(logText, "initialize2") || strings.Contains(logText, "swapbasein") {
		out.RaydiumRelated = true
	}
	if strings.Contains(logText, "pump") || strings.Contains(logText, "pumpswap") {
		out.PumpRelated = true
	}
	if strings.Contains(logText, "jito") || strings.Contains(logText, "bundle") {
		out.JitoRelated = true
	}
	if len(out.Signers) > 0 && (out.InitializeMint || out.CreateAccount) {
		out.CreatorCandidate = out.Signers[0]
	}
	if out.InitializeMint || out.CreateAccount {
		type fundingDelta struct {
			Address string
			Delta   int64
		}
		funding := []fundingDelta{}
		for address, delta := range out.LamportDeltas {
			if delta < -5000 {
				funding = append(funding, fundingDelta{Address: address, Delta: delta})
			}
		}
		sort.SliceStable(funding, func(i, j int) bool { return funding[i].Delta < funding[j].Delta })
		for _, item := range funding {
			out.FundingAccounts = append(out.FundingAccounts, item.Address)
		}
	}
}

func parseInstructionList(raw any, out *arvisTransactionEvidence, programSet, typeSet, mintSet map[string]bool) {
	instructions, ok := raw.([]any)
	if !ok {
		return
	}
	for _, entry := range instructions {
		instruction := asRadarMap(entry)
		programID := strings.TrimSpace(anyString(instruction["programId"]))
		if programID != "" {
			programSet[programID] = true
		}
		if program := strings.TrimSpace(anyString(instruction["program"])); program != "" {
			programSet[program] = true
		}
		parsed := asRadarMap(instruction["parsed"])
		instructionType := strings.ToLower(strings.TrimSpace(anyString(parsed["type"])))
		if instructionType != "" {
			typeSet[instructionType] = true
		}
		if strings.Contains(instructionType, "initializemint") {
			out.InitializeMint = true
		}
		if instructionType == "create" || strings.Contains(instructionType, "createaccount") {
			out.CreateAccount = true
		}
		info := asRadarMap(parsed["info"])
		for _, key := range []string{"mint", "tokenMint", "mintAddress"} {
			if mint := strings.TrimSpace(anyString(info[key])); isLikelyRadarSolanaAddress(mint) {
				mintSet[mint] = true
			}
		}
	}
}

func applyLamportDeltas(meta map[string]any, out *arvisTransactionEvidence) {
	pre, _ := meta["preBalances"].([]any)
	post, _ := meta["postBalances"].([]any)
	limit := len(out.AccountKeys)
	if len(pre) < limit {
		limit = len(pre)
	}
	if len(post) < limit {
		limit = len(post)
	}
	for i := 0; i < limit; i++ {
		out.LamportDeltas[out.AccountKeys[i]] = radarInt64(post[i]) - radarInt64(pre[i])
	}
}

func applyTokenBalanceDeltas(meta map[string]any, out *arvisTransactionEvidence, mintSet map[string]bool) {
	pre := tokenBalanceTotals(meta["preTokenBalances"], mintSet)
	post := tokenBalanceTotals(meta["postTokenBalances"], mintSet)
	for mint, value := range pre {
		out.TokenBalanceChanges[mint] -= value
	}
	for mint, value := range post {
		out.TokenBalanceChanges[mint] += value
	}
}

func tokenBalanceTotals(raw any, mintSet map[string]bool) map[string]float64 {
	out := map[string]float64{}
	items, ok := raw.([]any)
	if !ok {
		return out
	}
	for _, entry := range items {
		item := asRadarMap(entry)
		mint := strings.TrimSpace(anyString(item["mint"]))
		if mint == "" {
			continue
		}
		mintSet[mint] = true
		amount := asRadarMap(item["uiTokenAmount"])
		value := radarFloat(amount["uiAmount"])
		if value == 0 {
			value = radarFloat(amount["uiAmountString"])
		}
		if value == 0 {
			rawAmount := radarFloat(amount["amount"])
			decimals, decimalsOK := safeServiceIntFromInt64(radarInt64(amount["decimals"]))
			if decimalsOK && decimals >= 0 && decimals <= 18 && rawAmount > 0 && decimals > 0 {
				value = rawAmount / math.Pow10(decimals)
			} else {
				value = rawAmount
			}
		}
		out[mint] += value
	}
	return out
}

func buildTransactionMEVArm(req SecurityRadarRequest, tx arvisTransactionEvidence, generatedAt string) SecurityRadarVerdict {
	if !tx.Available || (!looksLikeSolanaSignature(req.Target) && !tx.ComputeBudgetRelated && !tx.JitoRelated) {
		return unavailableArm("MEV Shield", ModuleMEVShield, req, generatedAt, "A parsed transaction with priority-fee or bundle evidence is required.")
	}
	risk := 8
	if tx.ComputeBudgetRelated {
		risk += 12
	}
	if tx.FeeLamports >= 1_000_000 {
		risk += 18
	} else if tx.FeeLamports >= 100_000 {
		risk += 8
	}
	if tx.ComputeUnits >= 1_000_000 {
		risk += 12
	} else if tx.ComputeUnits >= 400_000 {
		risk += 5
	}
	if tx.WritableCount >= 12 {
		risk += 8
	}
	if tx.JitoRelated {
		risk -= 5
	}
	if risk < 1 {
		risk = 1
	}
	s := transactionArmSignals(tx, ModuleMEVShield)
	s["fee_lamports"] = tx.FeeLamports
	s["compute_units"] = tx.ComputeUnits
	s["compute_budget_program"] = tx.ComputeBudgetRelated
	s["jito_related"] = tx.JitoRelated
	s["scope_note"] = "priority and route exposure; slippage-specific sandwich simulation requires swap inputs"
	e := []string{fmt.Sprintf("Transaction fee: %d lamports; compute units: %d.", tx.FeeLamports, tx.ComputeUnits), fmt.Sprintf("Compute Budget program present: %t; Jito-related log evidence: %t.", tx.ComputeBudgetRelated, tx.JitoRelated), "This arm measures transaction priority and route exposure; it does not claim a confirmed sandwich attack without swap and slippage inputs."}
	return evidenceArm("MEV Shield", ModuleMEVShield, req, risk, s, e, generatedAt)
}

func buildLiquidityMovementTransactionArm(req SecurityRadarRequest, tx arvisTransactionEvidence, generatedAt string) SecurityRadarVerdict {
	if !tx.Available || !tx.RaydiumRelated || len(tx.TokenMints) < 2 {
		return unavailableArm("Liquidity Movement", ModuleLiquidityMovement, req, generatedAt, "A parsed Raydium transaction with at least two token balance surfaces is required.")
	}
	changed := 0
	for _, delta := range tx.TokenBalanceChanges {
		if math.Abs(delta) > 0 {
			changed++
		}
	}
	risk := 12
	if changed >= 2 {
		risk += 18
	}
	if tx.InnerInstructionCount >= 10 {
		risk += 8
	}
	if tx.FailedTransaction() {
		risk += 10
	}
	s := transactionArmSignals(tx, ModuleLiquidityMovement)
	s["raydium_related"] = true
	s["token_mint_count"] = len(tx.TokenMints)
	s["changed_token_surfaces"] = changed
	s["token_balance_changes"] = tx.TokenBalanceChanges
	e := []string{fmt.Sprintf("Raydium-related transaction observed with %d token mint surfaces.", len(tx.TokenMints)), fmt.Sprintf("Token balance changes detected on %d surfaces.", changed), fmt.Sprintf("Inner instructions observed: %d.", tx.InnerInstructionCount), "This is a movement signal; historical reserve snapshots are still required to classify a liquidity drain."}
	return evidenceArm("Liquidity Movement", ModuleLiquidityMovement, req, risk, s, e, generatedAt)
}

func buildCreatorLinkTransactionArm(req SecurityRadarRequest, tx arvisTransactionEvidence, generatedAt string) SecurityRadarVerdict {
	if !tx.Available || tx.CreatorCandidate == "" || (!tx.InitializeMint && !tx.CreateAccount) {
		return unavailableArm("Creator Link Analysis", ModuleCreatorLinkAnalysis, req, generatedAt, "A parsed mint or account initialization transaction with signer evidence is required.")
	}
	risk := 10
	if len(tx.Signers) >= 3 {
		risk += 8
	}
	if len(tx.FundingAccounts) >= 2 {
		risk += 14
	}
	if tx.PumpRelated {
		risk += 8
	}
	s := transactionArmSignals(tx, ModuleCreatorLinkAnalysis)
	s["creator_candidate"] = tx.CreatorCandidate
	s["signer_count"] = len(tx.Signers)
	s["funding_account_count"] = len(tx.FundingAccounts)
	s["initialize_mint"] = tx.InitializeMint
	s["scope_note"] = "initialization signer candidate, not identity attribution"
	e := []string{fmt.Sprintf("Initialization signer candidate: %s.", tx.CreatorCandidate), fmt.Sprintf("Signer count: %d; funding accounts with negative SOL delta: %d.", len(tx.Signers), len(tx.FundingAccounts)), "The address is reported as an initialization signer candidate; ARVIS does not claim real-world creator identity."}
	return evidenceArm("Creator Link Analysis", ModuleCreatorLinkAnalysis, req, risk, s, e, generatedAt)
}

func buildFundingClusterTransactionArm(req SecurityRadarRequest, tx arvisTransactionEvidence, generatedAt string) SecurityRadarVerdict {
	if !tx.Available || tx.CreatorCandidate == "" || len(tx.FundingAccounts) == 0 {
		return unavailableArm("Funding Cluster Detector", ModuleFundingClusterDetector, req, generatedAt, "Initialization funding deltas and signer evidence are required.")
	}
	risk := 8 + len(tx.FundingAccounts)*7
	if len(tx.FundingAccounts) >= 3 {
		risk += 12
	}
	if risk > 80 {
		risk = 80
	}
	s := transactionArmSignals(tx, ModuleFundingClusterDetector)
	s["creator_candidate"] = tx.CreatorCandidate
	s["funding_accounts"] = tx.FundingAccounts
	s["funding_account_count"] = len(tx.FundingAccounts)
	s["lamport_deltas"] = tx.LamportDeltas
	e := []string{fmt.Sprintf("Initialization candidate %s is linked to %d accounts with negative SOL balance deltas.", tx.CreatorCandidate, len(tx.FundingAccounts)), "Funding links are derived from the parsed transaction balance delta, not wallet ownership assumptions."}
	return evidenceArm("Funding Cluster Detector", ModuleFundingClusterDetector, req, risk, s, e, generatedAt)
}

func buildTransactionIntentProgramArm(req SecurityRadarRequest, tx arvisTransactionEvidence, generatedAt string) SecurityRadarVerdict {
	if !tx.Available || len(tx.ProgramIDs) == 0 {
		return unavailableArm("Program Relation Scan", ModuleProgramRelationScan, req, generatedAt, "Parsed transaction program, signer and instruction evidence is required for transaction intent.")
	}
	intent, reasons := classifyTransactionIntent(tx)
	s := transactionArmSignals(tx, ModuleProgramRelationScan)
	s["account_owner"] = ""
	s["account_executable"] = false
	s["is_token_mint"] = false
	s["transaction_intent"] = intent
	s["transaction_intent_reasons"] = reasons
	s["signers"] = tx.Signers
	s["signer_count"] = len(tx.Signers)
	s["writable_account_count"] = tx.WritableCount
	s["inner_instruction_count"] = tx.InnerInstructionCount
	s["token_mints"] = tx.TokenMints
	s["token_balance_changes"] = tx.TokenBalanceChanges
	s["lamport_deltas"] = tx.LamportDeltas
	s["scope_note"] = "Instruction intent is parsed transaction evidence; it is not actor identity, guilt or market-manipulation attribution."
	e := []string{
		fmt.Sprintf("Transaction intent classified as %s from parsed instruction and program evidence.", intent),
		fmt.Sprintf("Observed %d signer(s), %d writable account(s), %d program id(s) and %d inner instruction(s).", len(tx.Signers), tx.WritableCount, len(tx.ProgramIDs), tx.InnerInstructionCount),
		"Intent classification is evidence-only and cannot issue, raise, lower or override a grade.",
	}
	for _, reason := range reasons {
		e = append(e, "Intent evidence: "+reason)
	}
	arm := evidenceArm("Program Relation Scan", ModuleProgramRelationScan, req, 0, s, e, generatedAt)
	arm.Verdict = "Parsed transaction intent evidence attached to Program Relation Scan; final grade remains owned by EvaluateUnifiedRadarVerdict."
	arm.Recommendation = "Review signer, writable account, program and balance-delta evidence before making any transaction-intent claim."
	return arm
}

func classifyTransactionIntent(tx arvisTransactionEvidence) (string, []string) {
	reasons := []string{}
	if tx.InitializeMint {
		reasons = append(reasons, "initializeMint instruction observed")
	}
	if tx.CreateAccount {
		reasons = append(reasons, "account creation instruction observed")
	}
	if tx.RaydiumRelated {
		reasons = append(reasons, "Raydium-related program or log evidence observed")
	}
	if tx.PumpRelated {
		reasons = append(reasons, "Pump-related program or log evidence observed")
	}
	if tx.ComputeBudgetRelated {
		reasons = append(reasons, "Compute Budget program observed")
	}
	if tx.JitoRelated {
		reasons = append(reasons, "Jito or bundle log evidence observed")
	}
	if len(nonZeroTokenBalanceChanges(tx.TokenBalanceChanges)) > 0 {
		reasons = append(reasons, "token balance delta evidence observed")
	}
	if len(nonZeroLamportDeltas(tx.LamportDeltas)) > 0 {
		reasons = append(reasons, "SOL balance delta evidence observed")
	}
	for _, instructionType := range tx.InstructionTypes {
		switch {
		case strings.Contains(instructionType, "swap"), strings.Contains(instructionType, "buy"), strings.Contains(instructionType, "sell"):
			reasons = append(reasons, "trade/swap instruction type observed: "+instructionType)
		case strings.Contains(instructionType, "transfer"):
			reasons = append(reasons, "transfer instruction type observed: "+instructionType)
		case strings.Contains(instructionType, "mintto"), strings.Contains(instructionType, "burn"), strings.Contains(instructionType, "closeaccount"):
			reasons = append(reasons, "token-supply/account lifecycle instruction observed: "+instructionType)
		}
	}
	switch {
	case tx.InitializeMint || tx.CreateAccount:
		return "mint_or_account_initialization", reasons
	case tx.RaydiumRelated && len(tx.TokenMints) >= 2:
		return "liquidity_or_swap_interaction", reasons
	case tx.PumpRelated:
		return "pump_launch_or_trade_interaction", reasons
	case hasInstructionContaining(tx.InstructionTypes, "swap", "buy", "sell"):
		return "trade_or_swap", reasons
	case hasInstructionContaining(tx.InstructionTypes, "transfer") || len(nonZeroTokenBalanceChanges(tx.TokenBalanceChanges)) > 0 || len(nonZeroLamportDeltas(tx.LamportDeltas)) > 0:
		return "asset_transfer", reasons
	case tx.ComputeBudgetRelated || tx.JitoRelated:
		return "priority_or_bundle_routing", reasons
	default:
		return "program_interaction", reasons
	}
}

func hasInstructionContaining(values []string, needles ...string) bool {
	for _, value := range values {
		for _, needle := range needles {
			if strings.Contains(value, needle) {
				return true
			}
		}
	}
	return false
}

func nonZeroTokenBalanceChanges(values map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for key, value := range values {
		if math.Abs(value) > 0 {
			out[key] = value
		}
	}
	return out
}

func nonZeroLamportDeltas(values map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for key, value := range values {
		if value != 0 {
			out[key] = value
		}
	}
	return out
}

func transactionArmSignals(tx arvisTransactionEvidence, moduleID string) map[string]any {
	return map[string]any{
		"module_id":                 moduleID,
		"real_onchain_evidence":     true,
		"arm_evidence_available":    true,
		"evidence_status":           "verified_parsed_transaction",
		"data_quality":              "parsed_transaction_evidence",
		"evidence_source":           "solana_getTransaction_jsonParsed",
		"transaction_signature":     tx.Signature,
		"slot":                      tx.Slot,
		"block_time":                tx.BlockTime,
		"program_ids":               tx.ProgramIDs,
		"instruction_types":         tx.InstructionTypes,
		"actor_ruleset_version":     ActorDefenseRulesetVersion,
		"unified_radar_ruleset":     UnifiedRadarRulesetVersion,
		"evidence_row_standard":     "signature, slot, timestamp, source, destination, amount, program, verification_status",
		"numeric_score_disabled":    true,
		"grade_effect":              "none_at_arm_layer",
		"unverified_claims_allowed": false,
	}
}

func replaceArvisArm(arms []SecurityRadarVerdict, replacement SecurityRadarVerdict) {
	for i := range arms {
		if arms[i].ModuleID == replacement.ModuleID {
			arms[i] = replacement
			return
		}
	}
}

func verifiedArvisArmCount(arms []SecurityRadarVerdict) int {
	count := 0
	for _, arm := range arms {
		if arm.ModuleID == ModuleFinalVerdictEngine || !arm.Signed || arm.Signals == nil {
			continue
		}
		if ok, _ := arm.Signals["real_onchain_evidence"].(bool); ok {
			count++
		}
	}
	return count
}

func looksLikeSolanaSignature(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 80 || len(value) > 100 {
		return false
	}
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, r := range value {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

func radarFloat(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case jsonNumber:
		f, _ := strconv.ParseFloat(string(v), 64)
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f
	default:
		f, _ := strconv.ParseFloat(strings.TrimSpace(anyString(v)), 64)
		return f
	}
}

type jsonNumber string

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (tx arvisTransactionEvidence) FailedTransaction() bool {
	return false
}
