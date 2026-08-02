package handlers

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
)

type transactionGuardExplanationMovement struct {
	AssetType string `json:"asset_type"`
	Mint      string `json:"mint,omitempty"`
	AmountRaw string `json:"amount_raw"`
	Amount    string `json:"amount"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Account   string `json:"account,omitempty"`
	Evidence  string `json:"evidence"`
}

type transactionGuardExplanationAuthority struct {
	Kind         string `json:"kind"`
	Account      string `json:"account,omitempty"`
	Authority    string `json:"authority,omitempty"`
	Delegate     string `json:"delegate,omitempty"`
	NewAuthority string `json:"new_authority,omitempty"`
	AmountRaw    string `json:"amount_raw,omitempty"`
	Persistent   bool   `json:"persistent"`
	Explanation  string `json:"explanation"`
}

type transactionGuardExplanationRecipient struct {
	Address         string   `json:"address"`
	Roles           []string `json:"roles"`
	HistoricalMatch bool     `json:"historical_match"`
	HistoricalRisk  string   `json:"historical_risk,omitempty"`
	HistoricalIndex int      `json:"historical_risk_index,omitempty"`
}

type transactionGuardExplanationReason struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
}

type transactionGuardPreSigningExplanation struct {
	Available                bool                                   `json:"available"`
	Action                   string                                 `json:"action"`
	Headline                 string                                 `json:"headline"`
	PlainLanguageSummary     string                                 `json:"plain_language_summary"`
	RecommendedAction        string                                 `json:"recommended_action"`
	EvidenceStatus           string                                 `json:"evidence_status"`
	Sends                    []transactionGuardExplanationMovement  `json:"sends"`
	Receives                 []transactionGuardExplanationMovement  `json:"receives"`
	Authorities              []transactionGuardExplanationAuthority `json:"authorities"`
	Recipients               []transactionGuardExplanationRecipient `json:"recipients"`
	InvokedPrograms          []string                               `json:"invoked_programs"`
	Reasons                  []transactionGuardExplanationReason    `json:"reasons"`
	HiddenOrSensitiveActions []string                               `json:"hidden_or_sensitive_actions"`
	Limitations              []string                               `json:"limitations"`
}

func buildTransactionGuardV3Explanation(wallet string, assessment transactionFirewallAssessment, decoded transactionGuardDecodedTransaction, threat transactionGuardThreatHistoryAnalysis) transactionGuardPreSigningExplanation {
	wallet = strings.TrimSpace(wallet)
	out := transactionGuardPreSigningExplanation{
		Available: decoded.Available, Action: assessment.Action,
		Headline:          guardV3ExplanationHeadline(assessment.Action),
		RecommendedAction: guardV3ExplanationRecommendation(assessment.Action),
		Sends:             []transactionGuardExplanationMovement{}, Receives: []transactionGuardExplanationMovement{},
		Authorities: []transactionGuardExplanationAuthority{}, Recipients: []transactionGuardExplanationRecipient{},
		InvokedPrograms: append([]string{}, decoded.ProgramIDs...), Reasons: []transactionGuardExplanationReason{},
		HiddenOrSensitiveActions: []string{}, Limitations: append([]string{}, decoded.Limitations...),
	}
	sort.Strings(out.InvokedPrograms)
	if !decoded.Available {
		out.EvidenceStatus = "unavailable"
		out.PlainLanguageSummary = "The serialized transaction could not be decoded, so Koschei cannot explain what the signature would authorize."
		return out
	}

	out.Sends, out.Receives = guardV3ExplanationBalanceMovements(wallet, decoded)
	out.Authorities = guardV3ExplanationAuthorities(decoded.TokenOperations)
	out.Recipients = guardV3ExplanationRecipients(decoded, threat)
	out.Reasons = guardV3ExplanationReasons(assessment.Findings, 5)
	out.HiddenOrSensitiveActions = guardV3ExplanationSensitiveActions(decoded, assessment, threat)

	coreComplete := decoded.Complete && (!decoded.AutomaticBalance.Requested || decoded.AutomaticBalance.Complete) && (!(decoded.SignedIntent.Requested || decoded.SignedIntent.Required) || decoded.SignedIntent.Complete)
	switch {
	case coreComplete && threat.Complete:
		out.EvidenceStatus = "complete"
	case coreComplete && !threat.Required:
		out.EvidenceStatus = "complete_core_optional_history_unavailable"
	default:
		out.EvidenceStatus = "partial"
	}
	out.Limitations = append(out.Limitations, threat.Limitations...)
	out.Limitations = uniqueExplanationStrings(out.Limitations)
	out.PlainLanguageSummary = guardV3ExplanationSummary(out)
	return out
}

func guardV3ExplanationBalanceMovements(wallet string, decoded transactionGuardDecodedTransaction) ([]transactionGuardExplanationMovement, []transactionGuardExplanationMovement) {
	sends := []transactionGuardExplanationMovement{}
	receives := []transactionGuardExplanationMovement{}
	seen := map[string]bool{}
	explicitWalletSOL := big.NewInt(0)

	for _, transfer := range decoded.SOLTransfers {
		if wallet != "" && transfer.Source != wallet {
			continue
		}
		amount := normalizedPositiveBigInt(transfer.Lamports)
		if amount.Sign() == 0 {
			continue
		}
		explicitWalletSOL.Add(explicitWalletSOL, amount)
		movement := transactionGuardExplanationMovement{
			AssetType: "SOL", AmountRaw: amount.String(), Amount: formatGuardRawAmount(amount.String(), intPointer(9)),
			From: transfer.Source, To: transfer.Recipient, Evidence: "decoded_outer_system_instruction",
		}
		key := explanationMovementKey("send", movement)
		if !seen[key] {
			seen[key] = true
			sends = append(sends, movement)
		}
	}

	for _, account := range decoded.AutomaticBalance.Accounts {
		if !account.TokenAccount || strings.TrimSpace(account.TokenDeltaRaw) == "" {
			continue
		}
		delta, ok := new(big.Int).SetString(strings.TrimSpace(account.TokenDeltaRaw), 10)
		if !ok || delta.Sign() == 0 {
			continue
		}
		ownedBefore := wallet != "" && account.PreTokenOwner == wallet
		ownedAfter := wallet != "" && account.PostTokenOwner == wallet
		if wallet == "" {
			ownedBefore, ownedAfter = true, true
		}
		amount := new(big.Int).Abs(new(big.Int).Set(delta))
		decimals := guardV3ExplanationDecimals(decoded.TokenOperations, account.Address, account.Mint)
		movement := transactionGuardExplanationMovement{
			AssetType: "token", Mint: account.Mint, AmountRaw: amount.String(), Amount: formatGuardRawAmount(amount.String(), decimals),
			Account: account.Address, Evidence: "verified_rpc_simulation_balance_delta",
		}
		if delta.Sign() < 0 && ownedBefore {
			movement.From = firstNonEmptyString(wallet, account.PreTokenOwner)
			movement.To = guardV3TokenDestination(decoded.TokenOperations, account.Address)
			key := explanationMovementKey("send", movement)
			if !seen[key] {
				seen[key] = true
				sends = append(sends, movement)
			}
		} else if delta.Sign() > 0 && ownedAfter {
			movement.To = firstNonEmptyString(wallet, account.PostTokenOwner)
			movement.From = guardV3TokenSource(decoded.TokenOperations, account.Address)
			key := explanationMovementKey("receive", movement)
			if !seen[key] {
				seen[key] = true
				receives = append(receives, movement)
			}
		}
	}

	walletSpent := normalizedPositiveBigInt(decoded.AutomaticBalance.WalletSOLSpentLamports)
	if walletSpent.Cmp(explicitWalletSOL) > 0 {
		unattributed := new(big.Int).Sub(walletSpent, explicitWalletSOL)
		sends = append(sends, transactionGuardExplanationMovement{
			AssetType: "SOL", AmountRaw: unattributed.String(), Amount: formatGuardRawAmount(unattributed.String(), intPointer(9)),
			From: wallet, To: "network fees, rent or CPI-controlled accounts", Evidence: "verified_rpc_simulation_wallet_delta",
		})
	}

	for _, operation := range decoded.TokenOperations {
		if operation.Kind != "transfer" && operation.Kind != "transfer_checked" {
			continue
		}
		if wallet != "" && operation.Authority != wallet {
			continue
		}
		movement := transactionGuardExplanationMovement{
			AssetType: "token", Mint: operation.Mint, AmountRaw: operation.AmountRaw,
			Amount: formatGuardRawAmount(operation.AmountRaw, operation.Decimals), From: operation.Source, To: operation.Destination,
			Account: operation.Source, Evidence: "decoded_outer_token_instruction",
		}
		key := explanationMovementKey("send", movement)
		if !seen[key] {
			seen[key] = true
			sends = append(sends, movement)
		}
	}

	return sends, receives
}

func guardV3ExplanationAuthorities(operations []transactionGuardDecodedTokenOperation) []transactionGuardExplanationAuthority {
	out := []transactionGuardExplanationAuthority{}
	for _, operation := range operations {
		switch operation.Kind {
		case "approve", "approve_checked":
			out = append(out, transactionGuardExplanationAuthority{
				Kind: operation.Kind, Account: operation.Source, Authority: operation.Authority, Delegate: operation.Delegate,
				AmountRaw: operation.AmountRaw, Persistent: true,
				Explanation: "A delegate may spend up to the approved token amount without another owner signature until the allowance is exhausted or revoked.",
			})
		case "set_authority":
			out = append(out, transactionGuardExplanationAuthority{
				Kind: operation.Kind, Account: operation.Account, Authority: operation.Authority, NewAuthority: operation.NewAuthority,
				Persistent:  operation.NewAuthority != "revoked",
				Explanation: "Control of a token account or mint authority is changed after this transaction.",
			})
		case "close_account":
			out = append(out, transactionGuardExplanationAuthority{
				Kind: operation.Kind, Account: operation.Account, Authority: operation.Authority, NewAuthority: operation.Destination,
				Persistent: false, Explanation: "The token account is closed and its rent is sent to the destination address.",
			})
		case "freeze_account", "thaw_account":
			out = append(out, transactionGuardExplanationAuthority{
				Kind: operation.Kind, Account: operation.Account, Authority: operation.Authority,
				Persistent: operation.Kind == "freeze_account", Explanation: "The authority changes whether transfers from this token account are permitted.",
			})
		case "burn", "burn_checked":
			out = append(out, transactionGuardExplanationAuthority{
				Kind: operation.Kind, Account: operation.Account, Authority: operation.Authority, AmountRaw: operation.AmountRaw,
				Persistent: false, Explanation: "Tokens are permanently removed from this account and total supply.",
			})
		}
	}
	return out
}

func guardV3ExplanationRecipients(decoded transactionGuardDecodedTransaction, threat transactionGuardThreatHistoryAnalysis) []transactionGuardExplanationRecipient {
	roles := map[string]map[string]bool{}
	canonical := map[string]string{}
	add := func(address, role string) {
		address = strings.TrimSpace(address)
		if !looksLikeGuardPubkey(address) || role == "" {
			return
		}
		key := strings.ToLower(address)
		if roles[key] == nil {
			roles[key] = map[string]bool{}
			canonical[key] = address
		}
		roles[key][role] = true
	}
	for _, transfer := range decoded.SOLTransfers {
		add(transfer.Recipient, "sol_recipient")
	}
	for _, operation := range decoded.TokenOperations {
		if operation.Destination != "" {
			add(operation.Destination, "token_or_rent_destination")
		}
		if operation.Delegate != "" {
			add(operation.Delegate, "token_delegate")
		}
		if operation.NewAuthority != "" && operation.NewAuthority != "revoked" {
			add(operation.NewAuthority, "new_token_authority")
		}
	}
	threatByAddress := map[string]transactionGuardThreatSubject{}
	for _, subject := range threat.Subjects {
		threatByAddress[strings.ToLower(subject.Address)] = subject
	}
	keys := make([]string, 0, len(roles))
	for key := range roles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]transactionGuardExplanationRecipient, 0, len(keys))
	for _, key := range keys {
		roleList := make([]string, 0, len(roles[key]))
		for role := range roles[key] {
			roleList = append(roleList, role)
		}
		sort.Strings(roleList)
		subject, matched := threatByAddress[key]
		out = append(out, transactionGuardExplanationRecipient{
			Address: canonical[key], Roles: roleList, HistoricalMatch: matched,
			HistoricalRisk: subject.HighestRiskLevel, HistoricalIndex: subject.HighestRiskIndex,
		})
	}
	return out
}

func guardV3ExplanationReasons(findings []transactionFirewallFinding, limit int) []transactionGuardExplanationReason {
	values := append([]transactionFirewallFinding{}, findings...)
	sort.SliceStable(values, func(i, j int) bool {
		if values[i].Score == values[j].Score {
			return values[i].Code < values[j].Code
		}
		return values[i].Score > values[j].Score
	})
	out := []transactionGuardExplanationReason{}
	for _, finding := range values {
		if finding.Score <= 0 && len(out) > 0 {
			continue
		}
		out = append(out, transactionGuardExplanationReason{
			Code: finding.Code, Severity: finding.Severity, Title: finding.Title, Evidence: finding.Evidence,
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func guardV3ExplanationSensitiveActions(decoded transactionGuardDecodedTransaction, assessment transactionFirewallAssessment, threat transactionGuardThreatHistoryAnalysis) []string {
	out := []string{}
	for _, operation := range decoded.TokenOperations {
		switch operation.Kind {
		case "approve", "approve_checked":
			out = append(out, fmt.Sprintf("Token delegate approval: %s may spend up to %s raw units from %s.", operation.Delegate, operation.AmountRaw, operation.Source))
		case "set_authority":
			out = append(out, fmt.Sprintf("Token authority change: %s becomes %s on %s.", operation.Authority, operation.NewAuthority, operation.Account))
		case "close_account":
			out = append(out, fmt.Sprintf("Token account closure: %s closes and rent goes to %s.", operation.Account, operation.Destination))
		case "freeze_account":
			out = append(out, fmt.Sprintf("Token account freeze: %s can be frozen by %s.", operation.Account, operation.Authority))
		case "burn", "burn_checked":
			out = append(out, fmt.Sprintf("Token burn: %s raw units are permanently removed from %s.", operation.AmountRaw, operation.Account))
		}
	}
	for _, account := range decoded.AutomaticBalance.Accounts {
		if account.AccountClosed && account.TokenAccount {
			out = append(out, "Simulation confirms token account closure: "+account.Address+".")
		}
		if account.PreProgramOwner != "" && account.PostProgramOwner != "" && account.PreProgramOwner != account.PostProgramOwner {
			out = append(out, fmt.Sprintf("Account program owner changes from %s to %s for %s.", account.PreProgramOwner, account.PostProgramOwner, account.Address))
		}
	}
	if decoded.SignedIntent.Requested && !decoded.SignedIntent.Complete {
		out = append(out, "The signed UI intent does not fully match the serialized transaction or declared policy.")
	}
	if threat.SubjectsMatched > 0 {
		out = append(out, fmt.Sprintf("%d transaction subject(s) match prior Koschei-signed risk verdicts.", threat.SubjectsMatched))
	}
	if assessment.Action == "withhold" {
		out = append(out, "Koschei withheld a safe decision because required evidence is incomplete.")
	}
	return uniqueExplanationStrings(out)
}

func guardV3ExplanationSummary(value transactionGuardPreSigningExplanation) string {
	parts := []string{}
	if len(value.Sends) > 0 {
		parts = append(parts, fmt.Sprintf("%d outgoing asset movement(s)", len(value.Sends)))
	}
	if len(value.Receives) > 0 {
		parts = append(parts, fmt.Sprintf("%d incoming asset movement(s)", len(value.Receives)))
	}
	if len(value.Authorities) > 0 {
		parts = append(parts, fmt.Sprintf("%d authority-sensitive action(s)", len(value.Authorities)))
	}
	if len(value.Recipients) > 0 {
		parts = append(parts, fmt.Sprintf("%d recipient or delegate address(es)", len(value.Recipients)))
	}
	if len(parts) == 0 {
		parts = append(parts, "no explicit wallet asset movement was decoded")
	}
	return "Koschei observed " + strings.Join(parts, ", ") + ". Decision: " + strings.ToUpper(value.Action) + "."
}

func guardV3ExplanationHeadline(action string) string {
	switch action {
	case "block":
		return "Do not sign this transaction"
	case "warn":
		return "Review these transaction effects before signing"
	case "withhold":
		return "Koschei cannot safely clear this transaction"
	default:
		return "No blocking transaction evidence was observed"
	}
}

func guardV3ExplanationRecommendation(action string) string {
	switch action {
	case "block":
		return "Reject the signature request and leave the application."
	case "warn":
		return "Verify every recipient, amount and authority change before continuing."
	case "withhold":
		return "Do not treat the transaction as safe; retry only after all evidence sources are available."
	default:
		return "Proceed only if the displayed recipients, amounts and authorities match what you intended."
	}
}

func guardV3ExplanationDecimals(operations []transactionGuardDecodedTokenOperation, account, mint string) *int {
	for _, operation := range operations {
		if operation.Decimals == nil {
			continue
		}
		if mint != "" && operation.Mint == mint {
			value := *operation.Decimals
			return &value
		}
		if operation.Source == account || operation.Destination == account || operation.Account == account {
			value := *operation.Decimals
			return &value
		}
	}
	return nil
}

func guardV3TokenDestination(operations []transactionGuardDecodedTokenOperation, source string) string {
	for _, operation := range operations {
		if (operation.Kind == "transfer" || operation.Kind == "transfer_checked") && operation.Source == source {
			return operation.Destination
		}
	}
	return "simulation-observed destination"
}

func guardV3TokenSource(operations []transactionGuardDecodedTokenOperation, destination string) string {
	for _, operation := range operations {
		if (operation.Kind == "transfer" || operation.Kind == "transfer_checked") && operation.Destination == destination {
			return operation.Source
		}
	}
	return "simulation-observed source"
}

func formatGuardRawAmount(raw string, decimals *int) string {
	value := normalizedPositiveBigInt(raw)
	if decimals == nil || *decimals <= 0 {
		return value.String()
	}
	places := *decimals
	digits := value.String()
	if len(digits) <= places {
		digits = strings.Repeat("0", places-len(digits)+1) + digits
	}
	whole := digits[:len(digits)-places]
	fraction := strings.TrimRight(digits[len(digits)-places:], "0")
	if fraction == "" {
		return whole
	}
	return whole + "." + fraction
}

func normalizedPositiveBigInt(raw string) *big.Int {
	value := new(big.Int)
	if _, ok := value.SetString(strings.TrimSpace(raw), 10); !ok {
		return big.NewInt(0)
	}
	if value.Sign() < 0 {
		value.Abs(value)
	}
	return value
}

func explanationMovementKey(direction string, movement transactionGuardExplanationMovement) string {
	return strings.Join([]string{direction, movement.AssetType, movement.Mint, movement.AmountRaw, movement.From, movement.To, movement.Account}, "|")
}

func uniqueExplanationStrings(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func intPointer(value int) *int { return &value }
